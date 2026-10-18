Name:           logscrub
Version:        1.2.0
Release:        1%{?dist}
Summary:        Mask secrets and personal data in logs

License:        MIT
URL:            https://github.com/hbenali/logscrub
Source0:        %{name}-%{version}.tar.gz
# Go modules, vendored by scripts/build-srpm.sh: Copr builds have no network.
Source1:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  golang >= 1.26
BuildRequires:  go-rpm-macros

%description
logscrub reads logs on standard input or from files and masks API keys,
tokens, passwords, private keys and personal data such as email addresses,
so that the logs can be shared safely. It streams its input, handles very
long lines, and can replace values with stable pseudonyms.

%prep
%autosetup -n %{name}-%{version}
tar -xf %{SOURCE1}

%build
# %%gobuild builds in GOPATH mode and ignores go.mod, so call go directly.
# -B gobuildid gives the binary a build-id, which debuginfo needs.
export CGO_ENABLED=0
export GOFLAGS="-mod=vendor -buildmode=pie"
go build -ldflags "-B gobuildid -X main.version=%{version}" -o logscrub ./cmd/logscrub

%check
export GOFLAGS=-mod=vendor
go test ./...

%install
install -D -m 0755 logscrub %{buildroot}%{_bindir}/logscrub
install -D -m 0644 docs/man/logscrub.1 %{buildroot}%{_mandir}/man1/logscrub.1
install -D -m 0644 cmd/logscrub/completions/logscrub.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/logscrub
install -D -m 0644 cmd/logscrub/completions/_logscrub \
    %{buildroot}%{_datadir}/zsh/site-functions/_logscrub
install -D -m 0644 cmd/logscrub/completions/logscrub.fish \
    %{buildroot}%{_datadir}/fish/vendor_completions.d/logscrub.fish

%files
%license LICENSE
%doc README.md
%{_bindir}/logscrub
%{_mandir}/man1/logscrub.1*
%{_datadir}/bash-completion/completions/logscrub
%{_datadir}/zsh/site-functions/_logscrub
%{_datadir}/fish/vendor_completions.d/logscrub.fish

%changelog
* Sun Oct 18 2026 Houssem Ben Ali <hbenali.tn@gmail.com> - 1.2.0-1
- New upstream release 1.2.0
