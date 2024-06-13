import mongoose from "mongoose";
import config from "../config/config.js";

const connect = async () => await mongoose.connect(config.uri, {
    dbName:config.dbname
})
    .then((conn) => console.log(`Application connected with database ${conn.Connection.name}`))
    .catch((err) => {
        console.log("Db connection failed");
        console.error(err);
    })

export default connect;