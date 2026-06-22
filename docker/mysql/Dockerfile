FROM mysql:8.0

# 确保日志目录存在并设置权限
RUN mkdir -p /var/log/mysql && chown -R mysql:mysql /var/log/mysql

EXPOSE 3306

CMD ["mysqld"]
