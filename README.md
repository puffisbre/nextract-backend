# backend

## Tillfällig supabase-databas.

Databaslänken ligger i info.txt.

!!! Se till att varje gång köra `npx prisma db pull´ innan ni ska jobba med databasan för att hämta det aktuella schemat !!!

Den är redan seedad så den behövs inte köras igen.

<!-- # backend-dashboard
## Running locally
* `npm install` - Install the dependencies
* `npm run build` - Build the project
* Start the database and UI by running `docker-compose up -d` in the terminal
  * Verify the database is running by running `docker ps` or `docker container ls` in the terminal
* Delete the database and UI by running `docker-compose down -v` in the terminal
* The prisma.sh contains prisma commands and also starts the backend server. Run them individually or run `./prisma.sh` to start the backend server
* .env file is required to run the backend server. You can copy the `.env.example` file and rename it to .env. The .env file contains the database connection string and other environment variables required for the backend server to run. -->

## Docker Instructions
* Build the image `docker buildx build --target runner -t backend:test .`
* Create network `docker network create my-net`Only needs to be done once
* Run the image `docker run -p 3000:3000 --rm -h backend --network=my-net --env-file .env --name backendtest backend:test`
