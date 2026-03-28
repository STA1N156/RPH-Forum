FROM node:18-slim

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --production && npm install @img/sharp-linux-x64 --no-save

COPY server.js database.js ./
COPY public/ ./public/

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

ENV PORT=9191
ENV HOST=0.0.0.0
ENV DATA_DIR=/app/data
ENV NODE_ENV=production

EXPOSE 9191

CMD ["node", "server.js"]
