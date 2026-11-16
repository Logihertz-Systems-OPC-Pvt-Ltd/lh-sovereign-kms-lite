Name:           lh-sovereign-kms-lite
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-kms - GF(2^8) Shamir Lagrange Basis Interpolation at x = 0
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Self-hosted Go envelope Key Management Service (KMS) implementing GF(2^8) Shamir (M, N) threshold secret sharing unseal, AES-256-GCM KEK/DEK envelope encryption with canonical AAD binding, and zero-exposure key rotation.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-kms ]; then
    install -m 0755 bin/lh-kms %{buildroot}%{_bindir}/lh-kms
elif [ -f lh-kms ]; then
    install -m 0755 lh-kms %{buildroot}%{_bindir}/lh-kms
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-sovereign-kms-lite.
