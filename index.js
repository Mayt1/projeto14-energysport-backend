import express from 'express';
import cors from 'cors';
//import bcrypt from "bcrypt"
import dotenv from "dotenv";
//import { v4 as uuid } from 'uuid';

import { MongoClient } from "mongodb";
//import schemaUser from "./schemaUser.js";

dotenv.config();

const app = express(); // Cria um servidor
app.use(express.json());
app.use(cors());

app.get("/",(req, res) => {
    console.log("funfando")
    res.send("funfando aqui tb")
});

app.listen(process.env.PORTA, () => {
    console.log("Back-end funcionando, nao esquece de desligar a cada atualizaçao")
});
