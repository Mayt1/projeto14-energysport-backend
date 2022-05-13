import express from 'express';
import cors from 'cors';
import bcrypt from "bcrypt"
import dotenv from "dotenv";
//import { v4 as uuid } from 'uuid';

import { MongoClient } from "mongodb";
import schemaUser from "./schemaUser.js";

dotenv.config();

const app = express(); // Cria um servidor
app.use(express.json());
app.use(cors());
const mongoClient = new MongoClient(process.env.MONGO_URI);

app.post('/signup', async (req, res) => {

    const { name, email,  password, confirmPassword } = req.body;
    const hashSenha = bcrypt.hashSync(password, 10)
    try {
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const isUserExistOnList = await db.collection("users").findOne({name:name}); //verifica se ja tem usuario
        console.log(isUserExistOnList)
        if (isUserExistOnList) {
            console.log("ja tem user igual no banco")
            return res.sendStatus(404);
        }

        const validation = await schemaUser.validateAsync({
            name: name,
            email: email,
            password: password,
            confirmPassword: confirmPassword
        });

        if (!validation.error) {
            await db.collection("users").insertOne({
                name: name,
                email: email,
                password: hashSenha
            });
        } else {
            console.log(validation.error.details)
            return res.sendStatus(422);
        }
        res.status(201).send("Usuario cadastrado com sucesso");
    } catch (e) {
        console.error(e);
        res.sendStatus(422);
    }
});

app.get("/",(req, res) => {
    console.log("funfando")
    res.send("funfando aqui tb")
});

app.listen(process.env.PORTA, () => {
    console.log("Back-end funcionando, nao esquece de desligar a cada atualizaçao")
});
