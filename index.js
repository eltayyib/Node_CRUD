const express = require('express');
const { default: helmet } = require('helmet');
const cors = require('cors');
const cookieParser = require("cookie-parser")
const mongoose = require('mongoose');

const authRouter = require('./routers/authRouter');



const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use (cookieParser());

mongoose.connect(process.env.MONGO_URI).then(()=>{
    console.log ("database connected")
}).catch(err =>{
    console.log(err);

})


app.use('/api/auth',authRouter)
app.get('/', (req, res)=>{
    res.json({message:"hello from the server"});

});

app.listen(process.env.PORT, ()=>{
    console.log('listening....');

});