FROM alpine:3.19

# 安装 OpenSSH 和必要工具
RUN apk add --no-cache \
    openssh \
    bash \
    curl \
    iptables \
    nginx

# 创建 admin 用户
RUN adduser -D admin && \
    echo "admin:rescue123" | chpasswd && \
    echo "root:rescue123" | chpasswd

# 配置 SSH
RUN ssh-keygen -A && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "AllowUsers admin root" >> /etc/ssh/sshd_config

# 确保日志目录存在
RUN mkdir -p /var/log && \
    touch /var/log/auth.log /var/log/syslog /var/log/rescue.log

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
