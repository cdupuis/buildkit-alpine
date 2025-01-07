package alpine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/containerd/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/exporter/containerimage/image"
	"github.com/moby/buildkit/frontend/dockerui"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

type cf interface {
	CurrentFrontend() (*llb.State, error)
}

func forwardSingleResult(res *client.Result) (client.Reference, *image.Image, error) {
	ref, err := res.SingleRef()
	if err != nil {
		return nil, nil, err
	}

	if dt, ok := res.Metadata[exptypes.ExporterImageConfigKey]; ok {
		var img image.Image
		if err := json.Unmarshal(dt, &img); err != nil {
			return nil, nil, err
		}
		return ref, &img, nil
	}
	return ref, nil, nil
}

func Build(ctx context.Context, c client.Client) (*client.Result, error) {
	ui, err := dockerui.NewClient(c)
	if err != nil {
		return nil, err
	}

	var self llb.State
	if cc, ok := c.(cf); !ok {
		return nil, errors.Errorf("no support for frontend reexec, buildkit v0.10+ required")
	} else {
		st, err := cc.CurrentFrontend()
		if err != nil {
			return nil, err
		}
		self = *st
	}

	src, err := ui.ReadEntrypoint(ctx, "Yaml")
	if err != nil {
		return nil, err
	}

	ic, err := parse(src.Data)
	if err != nil {
		return nil, err
	}

	if ui.TargetPlatforms == nil && len(ic.Archs) > 0 {
		ui.TargetPlatforms = fromAlpinePlatforms(ic.Archs)
	}

	rb, err := ui.Build(ctx, func(ctx context.Context, platform *ocispecs.Platform, idx int) (client.Reference, *image.Image, error) {
		if platform == nil {
			p := platforms.DefaultSpec()
			platform = &p
		}

		opts := c.BuildOpts().Opts

		if urls, ok := opts["build-arg:urls"]; ok && urls != "" {
			res, img, err := installPkgs(ctx, c, self, *platform, ic)
			if err != nil {
				return nil, nil, err
			}
			ref, _, err := forwardSingleResult(res)
			if err != nil {
				return nil, nil, err
			}
			return ref, img, nil
		}

		res, err := buildPlatform(ctx, c, self, *platform, ic)
		if err != nil {
			return nil, nil, err
		}
		return forwardSingleResult(res)
	})
	if err != nil {
		return nil, err
	}

	for _, p := range ui.TargetPlatforms {
		for k, v := range ic.Annotations {
			rb.AddMeta(exptypes.AnnotationManifestDescriptorKey(&p, k), []byte(v))
		}
	}

	return rb.Finalize()
}

func isIgnoreCache(c client.Client) bool {
	if _, ok := c.BuildOpts().Opts["no-cache"]; ok {
		return true
	}
	return false
}

func initUser(self llb.State, p ocispecs.Platform, ic *ImageConfiguration) llb.State {
	userfs := llb.Scratch()
	groups := make([]string, 0)
	gidToGroup := make(map[uint32]string)
	users := make([]string, 0)

	if ic.Accounts.Root {
		groups = append(groups, "root:x:0:root")
		users = append(users, "root:x:0:root")
	}
	userfs = userfs.File(llb.Mkdir("/home", 0755)).File(llb.Mkdir("/etc", 0755))

	for _, group := range ic.Accounts.Groups {
		u := strings.Join(group.Members, ",")
		groups = append(groups, fmt.Sprintf("%s:x:%d:%s", group.GroupName, group.GID, u))
		gidToGroup[group.GID] = group.GroupName
	}

	for _, user := range ic.Accounts.Users {
		users = append(users, fmt.Sprintf("%s:x:%d:%d:%s:/home/%s:/sbin/nologin", user.UserName, user.UID, user.GID, user.UserName, user.UserName))
		userfs = userfs.File(
			llb.Mkdir(fmt.Sprintf("/home/%s", user.UserName), 0744,
				llb.WithUIDGID(int(user.UID), int(user.GID))),
			llb.WithCustomNamef("[%s] create home directory for %s", platforms.Format(p), user.UserName),
		)
	}
	userfs = userfs.File(
		llb.Mkfile("/etc/group", 0644, []byte(strings.Join(groups, "\n")+"\n")),
		llb.WithCustomNamef("[%s] add groups", platforms.Format(p)),
	).File(
		llb.Mkfile("/etc/passwd", 0644, []byte(strings.Join(users, "\n")+"\n")),
		llb.WithCustomNamef("[%s] add users", platforms.Format(p)),
	)

	return self.File(llb.Copy(userfs, "/", "/"), llb.WithCustomNamef("[%s] add users and groups", platforms.Format(p)))
}

func initOSRelease(_ client.Client, self llb.State, p ocispecs.Platform, ic *ImageConfiguration) llb.State {
	if ic.OSRelease == nil {
		return self
	}
	return self.File(
		llb.Mkfile("/etc/os-release", 0644, []byte(fmt.Sprintf("NAME=%s\nID=%s\nVERSION_ID=%s\nPRETTY_NAME=%s\nHOME_URL=%s\nBUG_REPORT_URL=%s\n", ic.OSRelease.Name, ic.OSRelease.ID, ic.OSRelease.VersionID, ic.OSRelease.PrettyName, ic.OSRelease.HomeURL, ic.OSRelease.BugReportURL))),
		llb.WithCustomNamef("[%s] add os-release", platforms.Format(p)),
	)
}

func initRepo(c client.Client, self llb.State, p ocispecs.Platform, repos []string, keys []string) llb.State {
	cmd := fmt.Sprintf(`sh -c "apk add --initdb --arch %s --root /out"`, alpinePlatform(p))

	ro := []llb.RunOption{llb.Shlex(cmd), llb.Network(llb.NetModeNone), llb.WithCustomNamef("[%s] initialize repo", platforms.Format(p))}
	if isIgnoreCache(c) {
		ro = append(ro, llb.IgnoreCache)
	}
	rootfs := self.Run(ro...).AddMount("/out", llb.Scratch())

	rootfs = rootfs.File(
		llb.Mkfile("/etc/apk/repositories", 0644, []byte(strings.Join(repos, "\n"))),
		llb.WithCustomNamef("[%s] add repositories", platforms.Format(p)),
	)

	rootfs = rootfs.File(
		llb.Copy(self, "/usr/share/apk/keys/"+alpinePlatform(p)+"/*", "/etc/apk/keys/", &llb.CopyInfo{
			AllowWildcard:      true,
			AllowEmptyWildcard: true,
			FollowSymlinks:     true,
		}),
		llb.WithCustomNamef("[%s] add keys", platforms.Format(p)),
	)

	if len(keys) > 0 {
		rootfs = rootfs.File(llb.Mkdir("/etc/apk/keys", 0755))

		for _, key := range keys {
			u, err := url.Parse(key)
			f := "__unnamed__"
			if err == nil {
				if base := path.Base(u.Path); base != "." && base != "/" {
					f = base
				}
			}
			perm := os.FileMode(0644)
			mode := &perm
			rootfs = rootfs.File(
				llb.Copy(
					llb.HTTP(key, llb.Filename(f), llb.WithCustomNamef("[%s] install repository key %s", platforms.Format(p), key)), f, "/etc/apk/keys/"+f, &llb.CopyInfo{
						CreateDestPath: true,
						Mode:           mode,
					}),
				llb.WithCustomNamef("[%s] copy repository key %s", platforms.Format(p), "/etc/apk/keys"),
				llb.IgnoreCache,
			)
		}
	}

	return rootfs
}

func buildBinaries(ctx context.Context, c client.Client, self, rootfs llb.State, p ocispecs.Platform, ic *ImageConfiguration) (llb.State, error) {
	files := ic.Contents.Files[platforms.Format(p)]
	for _, b := range files {
		rawURL := b.Url
		u, err := url.Parse(rawURL)
		f := "__unnamed__"
		if err == nil {
			if base := path.Base(u.Path); base != "." && base != "/" {
				f = base
			}
		}
		d, err := checksum(ctx, c, self, p, b.Checksum, f)
		if err != nil {
			return self, err
		}
		st := llb.HTTP(rawURL, llb.Filename(f), llb.Checksum(d), llb.WithCustomNamef("[%s] download file %s", platforms.Format(p), rawURL))
		perm := os.FileMode(0744)
		mode := &perm
		unpack := false
		if strings.HasSuffix(f, ".tar.gz") || strings.HasSuffix(f, ".tgz") {
			unpack = true
		}
		filefs := llb.Scratch().File(
			llb.Copy(st, f, b.Path, &llb.CopyInfo{
				CreateDestPath: true,
				Mode:           mode,
				AttemptUnpack:  unpack,
			}),
			llb.WithCustomNamef("[%s] copy file %s", platforms.Format(p), b.Path),
		)
		for _, exclude := range b.Excludes {
			pt := path.Join(b.Path, exclude)
			filefs = filefs.File(
				llb.Rm(pt, &llb.RmInfo{AllowWildcard: true, AllowNotFound: true}),
				llb.WithCustomNamef("[%s] remove file %s", platforms.Format(p), pt),
			)
		}
		rootfs = rootfs.File(llb.Copy(filefs, "/", "/"), llb.WithCustomNamef("[%s] installing files from %s at %s", platforms.Format(p), rawURL, b.Path))
	}
	return rootfs, nil
}

func buildPlatform(ctx context.Context, c client.Client, self llb.State, p ocispecs.Platform, ic *ImageConfiguration) (*client.Result, error) {
	rootfs := initRepo(c, self, p, ic.Contents.Repositories, ic.Contents.Keyring)

	// Trim version number off
	packages := make([]string, len(ic.Contents.Packages))
	for i, pkg := range ic.Contents.Packages {
		packages[i] = strings.Split(pkg, "=")[0]
	}

	cmd := fmt.Sprintf(`sh -c "ls -l /out/etc/apk/keys && apk update --root /out && apk fetch -R --simulate --root /out --update --url %s > /urls"`, strings.Join(packages, " "))

	ro := []llb.RunOption{llb.Shlex(cmd), llb.WithCustomNamef("[%s] fetch package locations", platforms.Format(p))}
	if isIgnoreCache(c) {
		ro = append(ro, llb.IgnoreCache)
	}
	run := self.Run(ro...)
	run.AddMount("/out", rootfs)

	def, err := run.Marshal(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}
	dt, err := res.Ref.ReadFile(ctx, client.ReadRequest{
		Filename: "/urls",
	})
	if err != nil {
		return nil, err
	}

	// Verify that the correct package versions are installed
	for _, pkg := range ic.Contents.Packages {
		if strings.Contains(pkg, "=") {
			alpinePkg := strings.Replace(pkg, "=", "-", 1)
			if !strings.Contains(string(dt), alpinePkg) {
				return nil, errors.Errorf("package %s not installed:\n%s", pkg, string(dt))
			}
		}
	}

	// TODO: this is a hack to get the urls from the solve result
	var urls []string
	for _, u := range strings.Split(string(dt), "\n") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		urls = append(urls, u)
	}

	opts := map[string]string{}
	for k, v := range c.BuildOpts().Opts {
		opts[k] = v
	}

	opts["platform"] = platforms.Format(p)
	opts["build-arg:urls"] = strings.Join(urls, ",")
	opts["build-arg:repositories"] = strings.Join(ic.Contents.Repositories, ",")
	if len(ic.Contents.Keyring) > 0 {
		opts["build-arg:keyring"] = strings.Join(ic.Contents.Keyring, ",")
	}

	opts["build-arg:cmd"] = strings.Join(ic.Cmd, "$$,$$")
	opts["build-arg:entrypoint"] = strings.Join(ic.Entrypoint, "$$,$$")
	opts["build-arg:workdir"] = ic.WorkDir
	opts["build-arg:run-as"] = ic.Accounts.RunAs
	for k, v := range ic.Environment {
		opts["build-arg:env:"+k] = v
	}

	inputs, err := c.Inputs(ctx)
	if err != nil {
		return nil, err
	}
	frontendInputs := make(map[string]*pb.Definition)
	for name, state := range inputs {
		def, err := state.Marshal(ctx)
		if err != nil {
			return nil, fmt.Errorf("330 %w", err)
		}
		frontendInputs[name] = def.ToPB()
	}

	return c.Solve(ctx, client.SolveRequest{
		Frontend:       "gateway.v0",
		FrontendOpt:    opts,
		FrontendInputs: frontendInputs,
	})
}

func installPkgs(ctx context.Context, c client.Client, self llb.State, p ocispecs.Platform, ic *ImageConfiguration) (*client.Result, *image.Image, error) {
	var repos, keyring, urls []string
	urlsStr := c.BuildOpts().Opts["build-arg:urls"]
	reposStr := c.BuildOpts().Opts["build-arg:repositories"]
	keyringStr := c.BuildOpts().Opts["build-arg:keyring"]

	if len(urlsStr) > 0 {
		urls = strings.Split(urlsStr, ",")
	}
	if len(reposStr) > 0 {
		repos = strings.Split(reposStr, ",")
	}
	if len(keyringStr) > 0 {
		keyring = strings.Split(keyringStr, ",")
	}
	rootfs := self

	if len(repos) > 0 || len(keyring) > 0 {
		rootfs = initRepo(c, self, p, repos, keyring)
	}
	rootfs = initOSRelease(c, rootfs, p, ic)
	rootfs = initUser(rootfs, p, ic)

	cmd := `sh -c "apk add --no-network --allow-untrusted --root /out /downloads/*.apk"`

	ro := []llb.RunOption{llb.Shlex(cmd), llb.Network(llb.NetModeNone), llb.WithCustomNamef("[%s] install packages", platforms.Format(p))}
	if isIgnoreCache(c) {
		ro = append(ro, llb.IgnoreCache)
	}
	run := self.Run(ro...)
	rootfs = run.AddMount("/out", rootfs)

	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, nil, err
		}
		base := path.Base(u.Path)
		run.AddMount("/downloads/"+base, llb.HTTP(rawURL, llb.Filename(base), llb.WithCustomNamef("[%s] download %s from %s", platforms.Format(p), base, rawURL)), llb.SourcePath(base))
	}
	var err error
	rootfs, err = buildBinaries(ctx, c, self, rootfs, p, ic)
	if err != nil {
		return nil, nil, err
	}

	def, err := rootfs.Marshal(ctx)
	if err != nil {
		return nil, nil, err
	}
	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, nil, err
	}

	img := &image.Image{
		Image: ocispecs.Image{
			Platform: ocispecs.Platform{
				Architecture: p.Architecture,
				OS:           p.OS,
				Variant:      p.Variant,
			},
		},
	}
	for k, v := range c.BuildOpts().Opts {
		if !strings.HasPrefix(k, "build-arg:") {
			continue
		}
		if k == "build-arg:cmd" && v != "" {
			img.Config.Cmd = strings.Split(v, "$$,$$")
		}
		if k == "build-arg:entrypoint" && v != "" {
			img.Config.Entrypoint = strings.Split(v, "$$,$$")
		}
		if k == "build-arg:workdir" && v != "" {
			img.Config.WorkingDir = v
		} else {
			img.Config.WorkingDir = "/"
		}
		if strings.HasPrefix(k, "build-arg:env:") {
			img.Config.Env = append(img.Config.Env, strings.TrimPrefix(k, "build-arg:env:")+"="+v)
		}
		if k == "build-arg:run-as" && v != "" {
			img.Config.User = v
		}
	}

	return res, img, nil
}

func parse(dt []byte) (*ImageConfiguration, error) {
	var ic ImageConfiguration
	// 1. Parse the image configuration to get the vars
	if err := yaml.Unmarshal(dt, &ic); err != nil {
		return nil, errors.Wrap(err, "failed to parse image configuration")
	}
	if ic.Vars == nil {
		return &ic, nil
	}

	// 2. Replace the vars in the image configuration
	c := string(dt)
	for k, v := range ic.Vars {
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			v = strings.TrimPrefix(v, "${")
			v = strings.TrimSuffix(v, "}")
			ref := strings.Split(v, ":")[0]
			exp := strings.Split(v, ":")[1]
			re, err := regexp.Compile(exp)
			if err != nil {
				return nil, err
			}
			if vv, ok := ic.Vars[ref]; ok {
				m := re.FindStringSubmatch(vv)
				if len(m) == 0 {
					return nil, fmt.Errorf("no match found for %q in %q", exp, vv)
				}
				v = m[1]
			}
		}
		c = strings.ReplaceAll(c, fmt.Sprintf("${%s}", k), v)
	}

	if err := yaml.Unmarshal([]byte(c), &ic); err != nil {
		return nil, errors.Wrap(err, "failed to parse image configuration")
	}

	return &ic, nil
}

func checksum(ctx context.Context, c client.Client, self llb.State, p ocispecs.Platform, entry string, filename string) (digest.Digest, error) {
	if strings.HasPrefix(entry, "https://") || strings.HasPrefix(entry, "http://") {
		u, err := url.Parse(entry)
		if err != nil {
			return "", err
		}
		base := path.Base(u.Path)
		sha256sum := llb.Scratch().File(
			llb.Copy(
				llb.HTTP(entry, llb.Filename(base), llb.WithCustomNamef("[%s] download sha256sum", platforms.Format(p))),
				"/", "/",
			),
		)

		def, err := sha256sum.Marshal(ctx)
		if err != nil {
			return "", err
		}
		res, err := c.Solve(ctx, client.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return "", err
		}
		dt, err := res.Ref.ReadFile(ctx, client.ReadRequest{
			Filename: "/" + base,
		})
		if err != nil {
			return "", err
		}

		re := regexp.MustCompile(`^(\S+)\s+(\S+)$`)
		lines := strings.Split(string(dt), "\n")
		for _, line := range lines {
			parts := re.FindStringSubmatch(line)
			if len(parts) < 3 {
				continue
			}
			if parts[2] == filename {
				return digest.Parse(fmt.Sprintf("sha256:%s", parts[1]))
			}
		}

		if len(lines) == 1 {
			return digest.Parse(fmt.Sprintf("sha256:%s", strings.TrimSpace(lines[0])))
		}

		return "", fmt.Errorf("checksum not found for %s in %s", filename, string(dt))
	}
	return digest.Parse(entry)
}
