FROM node:20-slim

WORKDIR /app

# Copy dependency files
COPY package*.json /app/

# Install node dependencies
RUN npm install

# Copy application files
COPY . /app/

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]
