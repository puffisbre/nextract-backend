# Use an official Node.js runtime as a parent image
FROM node:18-alpine AS base

WORKDIR /app

# Install bcrypt dependencies
RUN apk add --no-cache python3 make g++ openssl && rm -rf /var/cache/apk/*
COPY package*.json ./

# Stage 1
FROM base AS deps
RUN npm install -P

# Stage 2
FROM base AS builder

COPY --from=deps /app/node_modules ./node_modules
COPY . .


# Generate Prisma client
ARG DATABASE_URL
RUN npm run prisma:dbpull && \
    npm rebuild bcrypt --build-from-source && \
    npm run prisma:generate && \
    npm run build

# Stage 3
FROM base AS runner

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

# Expose port 3000 to the outside world
EXPOSE 3000

# Run the app when the container launches
CMD ["npm", "run", "start"]

