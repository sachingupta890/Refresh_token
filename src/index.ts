import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import connect from "./db/dbConfig.js";
import config from "./config/config.js";
import indexRoutes from "./routes/index.js"



const app = express();
const port = config.port;

connect();

app.get('/', (req, res) => {
  res.send(`routing is up`);
})

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: '*'
}))

app.use('/api/v1',indexRoutes)



app.listen(port, () => {
  console.log(`App is Up at Port ${port}`);
});

