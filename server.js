const express=require('express')
const {open}=require('sqlite')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const cors=require('cors')
const sqlite3=require('sqlite3')
const app=express()
const path=require('path')

app.use(cors())

app.use(express.json());

const dbPath=path.join(__dirname,'todoAppData.db')

let db=null

const initiateAndStartDatabaseServer=async()=>{
    try{
        db=await open({
            filename:dbPath,
            driver:sqlite3.Database
        })
        app.listen(3000,()=>{
            console.log('Backend Server is Running at http://localhost:3000/')
        })
    }catch (e){
        console.log(`Db Error ${e.message}`)
        process.exit(1)
    }
}


initiateAndStartDatabaseServer()


app.post('/Signup', async (request, response) => {
    const { username, email,password } = request.body; 
    try {
        // Hash the password here before inserting (use a library like bcrypt)
        const insertQuery = `INSERT INTO users (username, email,password) VALUES (?, ?, ?)`;
        const hashedPassword=await bcrypt.hash(password,10)
        await db.run(insertQuery, [username,email,hashedPassword]);
        response.status(201).json({ message: "Data received successfully Ram" });
    } catch (e) {
        console.error(e); // Log the error for debugging
        response.status(401).json({ message: 'Failed to store the data' });
    }
});


app.post('/login',async(req,res)=>{
    try{
        const {username,password}=req.body
        const selectUserQuery=`select * from users where username=?;`
        const dbUser=await db.get(selectUserQuery,[username])
        if(dbUser===undefined){
            res.status(400).json({message:'invalid User or password'})
        }else{
            const isMatchedPassword=await bcrypt.compare(password,dbUser.password)
            if(isMatchedPassword===true){
               const payload={
                username:username
               }
               const jwtToken=jwt.sign(payload,'secret_token')
               res.status(200).json({jwtToken})
            }else{
                res.status(400).json({message:'invalid User or password'})
            }
        }
    }catch (e){
        res.status(500).json({ error: `Error processing request: ${e.message}` });
    }
})


