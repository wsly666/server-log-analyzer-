FROM nginx:1.25-alpine

# 安装必要的工具
RUN apk add --no-cache curl

# 复制配置文件
COPY nginx.conf /etc/nginx/nginx.conf

# 复制网站页面
COPY html/ /usr/share/nginx/html/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
