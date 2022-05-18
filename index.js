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
    const { name,  password, confirmPassword } = req.body;
    const { user } = req.headers
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
            email: user,
            password: password,
            confirmPassword: confirmPassword
        });

        if (!validation.error) {
            await db.collection("users").insertOne({
                name: name,
                email: user,
                password: hashSenha
            });
        } else {
            console.log(validation.error.details)
            return res.sendStatus(402);
        }
        res.status(201).send("Usuario cadastrado com sucesso");
    } catch (e) {
        console.error(e);
        res.sendStatus(422);
    }
});

app.post('/login', async (req, res) => {
    const { password } = req.body;
    const {user} = req.headers
    try {
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const usere = await db.collection('users').findOne({ email: user }); //encontra usuario

        if (usere && bcrypt.compareSync(password, usere.password)) {
            const sessao = await db.collection("sessions").insertOne({
                userId: usere._id,
            })
            console.log(sessao.insertedId)
            const sessionId = { session: sessao.insertedId };
            const secretKey = process.env.JWT_SECRET;
            const configurationJwt = {expiresIn: 60*60*24*30 } //30dias em segundos
            const token = jwt.sign(sessionId, secretKey, configurationJwt);
            await db.collection("sessions").updateOne({_id: sessao.insertedId}, {$set: {'token': token}})
            let resposta={token:token, name:usere.name}
            res.send(resposta);
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

app.delete("/logout", async (req,res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');
    const secretKey = process.env.JWT_SECRET;
    if (!token) {//se n tiver token
            console.log("voce nao tem autorizaçao")
            return res.sendStatus(401);
    } else {
        try {//validatoken
            const sessionId = jwt.verify(token, secretKey);
            //console.log(sessionId.session) //sessionId.session mostra o conteudo que veio com o token, q é o id da sessao do usuario.
            await mongoClient.connect()
            const db = mongoClient.db(process.env.DATABASE);
            console.log(sessionId)
            const del = await db.collection("sessions").deleteOne({_id:new ObjectId(sessionId.session)}, (err) => {
                //new ObjectId
                console.log(del)
                if(err) {
                    return res.sendStatus(400)
                } else {
                    return res.sendStatus(204)
                }
            })
        } catch (e) {
            console.error("token invalido" + e);
            return res.sendStatus(422);
        }
    }
});

app.get("/products", async (req, res) => {
    const {type} = req.query;
    const limit = parseInt(req.query.limit);
	console.log(limit, type)
    if(!type){
        if(!limit){
            //retorna tudo
            try {
                await mongoClient.connect()
                const db = mongoClient.db(process.env.DATABASE);
                const allproducts = await db.collection("products").find().toArray();
                console.log("tamo certo sem filtro");
                if(allproducts) {
                    res.send(allproducts);
                } else {
                    console.log("Não foi possivel encontrar os produtos")
                    res.sendStatus(401);
                }
            } catch (e) {
                console.error("Banco nao foi conectado" + e);
                return res.sendStatus(422);
            }
        } else{
            //sem filtro mas com limite de produtos
            try {
                await mongoClient.connect()
                const db = mongoClient.db(process.env.DATABASE);
                const typedProducts = await db.collection("products").find().limit(limit).toArray();
                console.log("tamo certo sem filtro mas com limite");
                if(typedProducts) {
                    res.send(typedProducts);
                } else {
                    console.log("Não foi possivel encontrar os produtos")
                    res.sendStatus(401);
                }
            } catch (e) {
                console.error("Banco nao foi conectado" + e);
                return res.sendStatus(422);
            } 
        }
    }else{
        console.log("tem tipo, entao retorna so daquele tipo")
        if(!limit){
            try {
                await mongoClient.connect()
                const db = mongoClient.db(process.env.DATABASE);
                const typedProducts = await db.collection("products").find({type: type}).toArray();
                console.log("tamo certo filtro com tipo sem limite");
                if(typedProducts) {
                    res.send(typedProducts);
                } else {
                    console.log("Não foi possivel encontrar os produtos")
                    res.sendStatus(401);
                }
            } catch (e) {
                console.error("Banco nao foi conectado" + e);
                return res.sendStatus(422);
            }
        } else{
            try {
                await mongoClient.connect()
                const db = mongoClient.db(process.env.DATABASE);
                const typedProducts = await db.collection("products").find({type: type}).limit(limit).toArray();
                console.log("tamo certo filtro com tipo e limite");
                if(typedProducts) {
                    res.send(typedProducts);
                } else {
                    console.log("Não foi possivel encontrar os produtos")
                    res.sendStatus(401);
                }
            } catch (e) {
                console.error("Banco nao foi conectado" + e);
                return res.sendStatus(422);
            } 
        }
    }
});

app.post("/inserir", async (req, res) => {

    const { name, img, type, price, sale, parcel } = req.body;
    try {
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        await db.collection("products").insertOne({
            name: name,
            img: img,
            type: type,
            price: price,
            sale: sale,
            parcel: parcel
        });
        res.status(201).send("Produto cadastrado com sucesso");
    } catch (e) {
        console.error(e);
        res.sendStatus(422);
    }
});

app.post("/cart", async (req, res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');
    const secretKey = process.env.JWT_SECRET;
    if (!token) {//se tiver token
            console.log("voce nao tem autorizaçao")
            return res.sendStatus(401);
        }
    const {idProd} = req.body;
    try {
        const sessionId = jwt.verify(token, secretKey);
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const {userId} = await db.collection("sessions").findOne({_id: new ObjectId(sessionId.session)})
        console.log(userId);
        if(userId) {
            const idCart = await db.collection("cart").findOne({idProd:idProd})
            if(!idCart){
                await db.collection("cart").insertOne({
                    idProd: idProd,
                    idUser: userId,
                    qtd:1  
                });
                res.status(201).send(valor);
            } else {
                console.log(idCart)
                await db.collection("cart").updateOne({idProd:idCart.idProd}, {
                $inc: {
                    qtd: 1
                }
            })
            res.status(201).send("Produto cadastrado no carrinho com sucesso"); 
            }
        } else {
            console.log("Não foi possivel encontrar o usuario nessa sessão")
            res.sendStatus(401);
        }
    } catch (e) {
        console.error("token invalido" + e);
        return res.status(422).send(e.message);
    }
});

app.put("/cart", async (req, res) => {
    const {authorization} = req.headers;
    const token = authorization?.replace('Bearer ', '');
    const secretKey = process.env.JWT_SECRET;
    if (!token) {//se tiver token
            console.log("voce nao tem autorizaçao")
            return res.sendStatus(401);
    }
    try {
        const sessionId = jwt.verify(token, secretKey);
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const {userId} = await db.collection("sessions").findOne({_id: new ObjectId(sessionId.session)})
        //console.log(userId);
        const {idProd, qtd} = req.body;
        if(userId) {
            const carrinho = await db.collection("cart").find({idUser: userId, idProd:idProd}).toArray();
            await db.collection("cart").updateOne({idProd:idProd}, 
                {$set: {
                    qtd: qtd
                }})
            res.status(201).send("Mudança feita com sucesso");
        } else {
            console.log("Não foi possivel encontrar o usuario nessa sessão")
            res.sendStatus(401);
        }
    } catch (e) {
        console.error("token invalido" + e);
        return res.sendStatus(422);
    }
});

app.get("/cart", async (req, res) => {
    const {authorization} = req.headers;
    const token = authorization?.replace('Bearer ', '');
    const secretKey = process.env.JWT_SECRET;
    if (!token) {//se tiver token
            console.log("voce nao tem autorizaçao")
            return res.sendStatus(401);
        }
    try {
        const sessionId = jwt.verify(token, secretKey);
        await mongoClient.connect()
        const db = mongoClient.db(process.env.DATABASE);
        const {userId} = await db.collection("sessions").findOne({_id: new ObjectId(sessionId.session)})
        if(userId) {
            const carrinho = await db.collection("cart").find({idUser: userId}).toArray();
            //pega o idProd do vetor de objetos carrinho e para cada um deles, encontrar os dados e jogar em um vetor de objeto
            //console.log(carrinho.idProd)
            let idsprodutos = []
            for(let i=0; i<carrinho.length; i++){
                let aux = carrinho[i].idProd;
                idsprodutos=[...idsprodutos, aux];
                console.log(idsprodutos);
            }
            let respostas = []
            for(let j=0; j<idsprodutos.length; j++){
                const valor = await db.collection("products").findOne({_id:new ObjectId(idsprodutos[j])});
                respostas=[...respostas, {...valor, qtd:carrinho[j].qtd}];
                console.log(respostas);
            }
            res.status(201).send(respostas);
        } else {
            console.log("Não foi possivel encontrar o usuario nessa sessão")
            res.sendStatus(401);
        }
    } catch (e) {
        console.error("token invalido" + e);
        return res.sendStatus(422);
    }
});

//DELETE cart
//POST demand



const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log("Back-end funcionando, nao esquece de desligar a cada atualizaçao")
});
