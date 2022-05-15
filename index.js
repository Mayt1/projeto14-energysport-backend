import express from 'express';
import cors from 'cors';
import bcrypt from "bcrypt"
import dotenv from "dotenv";
//import { v4 as uuid } from 'uuid';
import jwt from "jsonwebtoken"

import { MongoClient, ObjectId } from "mongodb";
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

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const user = await db.collection('users').findOne({ email: email }); //encontra usuario

        if (user && bcrypt.compareSync(password, user.password)) {
            const sessao = await db.collection("sessions").insertOne({
                userId: user._id,
            })
            console.log(sessao.insertedId)
            const sessionId = { session: sessao.insertedId };
            const secretKey = process.env.JWT_SECRET;
            const configurationJwt = {expiresIn: 60*60*24*30 } //30dias em segundos
            const token = jwt.sign(sessionId, secretKey, configurationJwt);
            await db.collection("sessions").updateOne({_id: sessao.insertedId}, {$set: {'token': token}})
            res.send(token);
        } else {
            console.log("usuario nao encontrado ou senha incorreta")
            res.sendStatus(404);
        }
    } catch (e) {
        console.error("Banco de dados nao foi conectado, tente novamente" + e);
        res.sendStatus(422);
    }
});

app.get("/usuario", async (req, res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');
    const secretKey = process.env.JWT_SECRET;
    if (!token) {//se tiver token
            console.log("voce nao tem autorizaçao")
            return res.sendStatus(401);
        }
    try {//validatoken
        const sessionId = jwt.verify(token, secretKey);
	    //console.log(sessionId.session) //sessionId.session mostra o conteudo que veio com o token, q é o id da sessao do usuario.
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const {userId} = await db.collection("sessions").findOne({_id: new ObjectId(sessionId.session)})
        console.log(userId);
        const user = await db.collection("users").findOne({_id: userId});
        console.log(user);
        if(user) {
            delete user.password; // deletando a propriedade password
            res.send(user);
        } else {
            console.log("Não foi possivel encontrar o usuario nessa sessão")
            res.sendStatus(401);
        }
    } catch (e) {
        console.error("token invalido" + e);
        return res.sendStatus(422);
    }
});

app.post("/logout", async (req,res) => {
    //

});

app.listen(process.env.PORTA, () => {
    console.log("Back-end funcionando, nao esquece de desligar a cada atualizaçao")
});
