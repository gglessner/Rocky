# Use Rocky Linux 8.6 as base image (has kernel 4.18.0 and glibc 2.28 - same as Red Hat 8.10)
FROM rockylinux/rockylinux:latest

# Set metadata
LABEL maintainer="Garland Glessner <gglessner@gmail.com>"
LABEL description="Rocky Linux 8.6 Docker Image with kernel 4.18.0 and glibc 2.28 - Compiled Exploits Generator"
LABEL version="8.6"
LABEL license="GPL-3.0"

# Update system packages
RUN dnf update -y && \
    dnf clean all

# Install common utilities and development tools
RUN dnf install -y \
    curl \
    wget \
    vim \
    nano \
    git \
    tar \
    gzip \
    unzip \
    net-tools \
    bind-utils \
    gcc \
    gcc-c++ \
    make \
    glibc-devel \
    kernel-headers \
    kernel-devel \
    libcap-devel \
    libseccomp-devel \
    libselinux-devel \
    libacl-devel \
    libattr-devel \
    libffi-devel \
    binutils \
    binutils-devel \
    elfutils-libelf-devel \
    zlib-devel \
    openssl-devel \
    ncurses-devel \
    readline-devel \
    sqlite-devel \
    && dnf clean all

# Set working directory
WORKDIR /root

# Create a non-root user (optional but recommended)
RUN useradd -m -s /bin/bash rocky && \
    echo "rocky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy comprehensive compilation script and set permissions (as root)
COPY comprehensive-compile-all.sh /home/rocky/comprehensive-compile-all.sh
RUN chown rocky:rocky /home/rocky/comprehensive-compile-all.sh && \
    chmod +x /home/rocky/comprehensive-compile-all.sh

# Switch to non-root user
USER rocky
WORKDIR /home/rocky

# Clone Linux Privilege Escalation Exploits repository
RUN git clone https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git && \
    chmod -R 755 Linux-Privilege-Escalation-Exploits

# Run comprehensive compilation script to compile all possible exploits
RUN ./comprehensive-compile-all.sh && \
    # Set proper permissions
    chmod -R 755 /home/rocky/working-exploits && \
    # Create archive of compiled exploits
    cd /home/rocky && \
    tar -czf compiled-exploits.tgz working-exploits/ && \
    chmod 644 compiled-exploits.tgz && \
    # Create README for working exploits
    cd /home/rocky/working-exploits && \
    echo '# Working Privilege Escalation Exploits' > README.md && \
    echo '' >> README.md && \
    echo '## Successfully Compiled Exploits' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2021-4034 (PwnKit)' >> README.md && \
    echo '- **Description**: polkit privilege escalation vulnerability' >> README.md && \
    echo '- **Binary**: ./CVE-2021-4034/cve-2021-4034-poc' >> README.md && \
    echo '- **Affects**: polkit/policykit-1 <=0.105-31' >> README.md && \
    echo '- **Usage**: ./CVE-2021-4034/cve-2021-4034-poc' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2021-3493' >> README.md && \
    echo '- **Description**: Linux kernel privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2021-3493/exploit' >> README.md && \
    echo '- **Usage**: ./CVE-2021-3493/exploit' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2021-22555 (exp1)' >> README.md && \
    echo '- **Description**: Linux kernel netfilter privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2021-22555-exp1/exploit' >> README.md && \
    echo '- **Affects**: Linux kernel 2.6.19-5.10' >> README.md && \
    echo '- **Usage**: ./CVE-2021-22555-exp1/exploit' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2019-13272' >> README.md && \
    echo '- **Description**: Linux kernel ptrace privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2019-13272/CVE-2019-13272' >> README.md && \
    echo '- **Affects**: Linux kernel 4.10-5.1.17' >> README.md && \
    echo '- **Usage**: ./CVE-2019-13272/CVE-2019-13272' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2017-7308' >> README.md && \
    echo '- **Description**: Linux kernel AF_PACKET privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2017-7308/poc' >> README.md && \
    echo '- **Affects**: Linux kernel 4.10-4.11' >> README.md && \
    echo '- **Usage**: ./CVE-2017-7308/poc' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2017-6074' >> README.md && \
    echo '- **Description**: Linux kernel DCCP privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2017-6074/poc' >> README.md && \
    echo '- **Affects**: Linux kernel 2.6.18-4.9' >> README.md && \
    echo '- **Usage**: ./CVE-2017-6074/poc' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2017-5123' >> README.md && \
    echo '- **Description**: Linux kernel waitid privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2017-5123/43029' >> README.md && \
    echo '- **Affects**: Linux kernel 4.13-4.13.4' >> README.md && \
    echo '- **Usage**: ./CVE-2017-5123/43029' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2017-8890' >> README.md && \
    echo '- **Description**: Linux kernel netlink privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2017-8890/exp-ret2usr, ./CVE-2017-8890/exp-smep' >> README.md && \
    echo '- **Affects**: Linux kernel 2.6.19-4.11' >> README.md && \
    echo '- **Usage**: ./CVE-2017-8890/exp-ret2usr or ./CVE-2017-8890/exp-smep' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2016-5195 (Dirty COW) exp1' >> README.md && \
    echo '- **Description**: Linux kernel race condition privilege escalation' >> README.md && \
    echo '- **Binary**: ./CVE-2016-5195-exp1/dirtycow' >> README.md && \
    echo '- **Affects**: Linux kernel 2.6.22-4.8' >> README.md && \
    echo '- **Usage**: ./CVE-2016-5195-exp1/dirtycow' >> README.md && \
    echo '' >> README.md && \
    echo '### CVE-2016-5195 (Dirty COW) exp2' >> README.md && \
    echo '- **Description**: Linux kernel race condition privilege escalation (alt)' >> README.md && \
    echo '- **Binary**: ./CVE-2016-5195-exp2/40611' >> README.md && \
    echo '- **Affects**: Linux kernel 2.6.22-4.8' >> README.md && \
    echo '- **Usage**: ./CVE-2016-5195-exp2/40611' >> README.md && \
    echo '' >> README.md && \
    echo '## System Information' >> README.md && \
    echo '- **Target**: Red Hat 8.10 (Ootpa) compatible' >> README.md && \
    echo '- **glibc**: 2.28' >> README.md && \
    echo '- **Kernel**: 4.18.0 series' >> README.md && \
    echo '- **Architecture**: x86_64' >> README.md && \
    echo '' >> README.md && \
    echo '## Usage' >> README.md && \
    echo 'All exploits are pre-compiled and ready to run on vulnerable systems.' >> README.md && \
    echo 'Copy the entire working-exploits directory to your target system.' >> README.md

# Set default command
CMD ["/bin/bash"]

