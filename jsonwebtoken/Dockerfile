FROM node:20-slim
WORKDIR /app
RUN npm init -y && npm install express jsonwebtoken@9.0.0
COPY app.js .
CMD ["node", "app.js"]