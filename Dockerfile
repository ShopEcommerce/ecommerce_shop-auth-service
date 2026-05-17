FROM node:20-alpine AS builder

WORKDIR /app

COPY shared/teleshop-common-1.0.0.tgz ./shared/
COPY shared/teleshop-common-1.0.3.tgz ./shared/
COPY auth-service/package*.json ./auth-service/

WORKDIR /app/auth-service
RUN npm ci

COPY auth-service/ ./
RUN npx prisma generate && npm run build

FROM node:20-alpine AS runner

WORKDIR /app/auth-service
ENV NODE_ENV=production

COPY --from=builder /app/auth-service /app/auth-service

EXPOSE 3001
CMD ["sh", "-c", "npx prisma db push --skip-generate && node dist/index.js"]
