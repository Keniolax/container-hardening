# The naive image: one stage, a full Debian base, everything run as root.
# Built only to measure against. It is never pushed.
FROM node:24
WORKDIR /juice-shop
COPY . .
RUN npm install -g typescript@6.0.3 && npm install --omit=dev
EXPOSE 3000
CMD ["npm", "start"]
