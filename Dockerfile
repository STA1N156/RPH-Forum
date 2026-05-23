FROM node:18-slim

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --include=optional

COPY server.js database.js ./
COPY public/ ./public/

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

ENV PORT=9191
ENV HOST=0.0.0.0
ENV DATA_DIR=/app/data
ENV NODE_ENV=production

EXPOSE 9191

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD node -e "const http=require('http');const req=http.get('http://127.0.0.1:' + (process.env.PORT || 9191) + '/health',res=>process.exit(res.statusCode===200?0:1));req.on('error',()=>process.exit(1));req.setTimeout(4000,()=>{req.destroy();process.exit(1);});"

CMD ["node", "server.js"]
