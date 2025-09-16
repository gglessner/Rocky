# Use Rocky Linux 8.6 as base image (has kernel 4.18.0 and glibc 2.28 - same as Red Hat 8.10)
FROM rockylinux/rockylinux:latest

# Set metadata
LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="Rocky Linux 8.6 Docker Image with kernel 4.18.0 and glibc 2.28"
LABEL version="8.6"

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
    && dnf clean all

# Set working directory
WORKDIR /root

# Create a non-root user (optional but recommended)
RUN useradd -m -s /bin/bash rocky && \
    echo "rocky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy exploit testing script and set permissions (as root)
COPY test-exploits.sh /home/rocky/test-exploits.sh
RUN chown rocky:rocky /home/rocky/test-exploits.sh && \
    chmod +x /home/rocky/test-exploits.sh

# Switch to non-root user
USER rocky
WORKDIR /home/rocky

# Clone Linux Privilege Escalation Exploits repository
RUN git clone https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git && \
    chmod -R 755 Linux-Privilege-Escalation-Exploits

# Create working exploits directory and copy successfully compiled exploits
RUN mkdir -p /home/rocky/working-exploits && \
    cd Linux-Privilege-Escalation-Exploits && \
    # Copy CVE-2021-4034 (PwnKit)
    cp -r 2021/CVE-2021-4034 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2021-4034 && \
    gcc -o cve-2021-4034-poc cve-2021-4034-poc.c && \
    # Copy CVE-2021-3493
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2021/CVE-2021-3493 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2021-3493 && \
    gcc -o exploit exploit.c && \
    # Copy CVE-2021-22555 exp-1
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2021/CVE-2021-22555/exp-1 /home/rocky/working-exploits/CVE-2021-22555-exp1 && \
    cd /home/rocky/working-exploits/CVE-2021-22555-exp1 && \
    gcc -o exploit exploit.c && \
    # Copy CVE-2019-13272
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2019/CVE-2019-13272 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2019-13272 && \
    gcc -o CVE-2019-13272 CVE-2019-13272.c && \
    # Copy CVE-2017-7308
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2017/CVE-2017-7308 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2017-7308 && \
    gcc -o poc poc.c && \
    # Copy CVE-2017-6074
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2017/CVE-2017-6074 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2017-6074 && \
    gcc -o poc poc.c && \
    # Copy CVE-2017-5123
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2017/CVE-2017-5123 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2017-5123 && \
    gcc -o 43029 43029.c && \
    # Copy CVE-2017-8890 (with pthread linking)
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2017/CVE-2017-8890 /home/rocky/working-exploits/ && \
    cd /home/rocky/working-exploits/CVE-2017-8890 && \
    gcc -o exp-ret2usr exp-ret2usr.c -lpthread && \
    gcc -o exp-smep exp-smep.c -lpthread && \
    # Copy CVE-2016-5195 (Dirty COW) exp-1
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2016/CVE-2016-5195/exp-1 /home/rocky/working-exploits/CVE-2016-5195-exp1 && \
    cd /home/rocky/working-exploits/CVE-2016-5195-exp1 && \
    gcc -o dirtycow dirty.c -lpthread -lcrypt && \
    # Copy CVE-2016-5195 (Dirty COW) exp-2
    cd /home/rocky/Linux-Privilege-Escalation-Exploits && \
    cp -r 2016/CVE-2016-5195/exp-2 /home/rocky/working-exploits/CVE-2016-5195-exp2 && \
    cd /home/rocky/working-exploits/CVE-2016-5195-exp2 && \
    gcc -o 40611 40611.c -lpthread && \
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

