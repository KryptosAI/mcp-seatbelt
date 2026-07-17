FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY dist/ ./dist/
COPY templates/ ./templates/
EXPOSE 9420 9421
ENTRYPOINT ["node", "dist/index.js"]
CMD ["proxy"]
