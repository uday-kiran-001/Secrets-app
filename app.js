
require("dotenv").config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
// const encrypt=require("mongoose-encryption");
// const md5=require("md5");
// const bcrypt=require("bcrypt");
// const saltRounds=10;
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app=express();
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static(__dirname+"/"));
app.use(session({
    secret:process.env.SECRET,
    resave:false,              // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
    // cookie:{secure:true}
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.set("strictQuery", false);
mongoose.connect("mongodb://127.0.0.1:27017/authDB");


const userSchema= new mongoose.Schema({
    username:String,
    password:String,
    googleId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret:process.env.SECRET, encryptedFields:["password"] }); // This is used for "mongoose-encryption" npm package

const UserModel=new mongoose.model("user",userSchema);
passport.use(UserModel.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id); 
});
passport.deserializeUser(function(id, done) {
    UserModel.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
    }, function(accessToken, refreshToken, profile, cb) {
        console.log("Profile : ", profile);
        UserModel.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
        });
    }
));


//---------------------------------------------------- Post -----------------------------------------------------//

app.post("/register",function(req,res){
    const username=req.body.username;
    const password=req.body.password;

    UserModel.register({username:username}, password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local", {failureRedirect:"/register",failureMessage:true})(req,res, function(){
                res.redirect("/secrets");
            });
        }
    });
    
});

app.post("/login",function(req,res){
    const user=new UserModel({
        username:req.body.username,
        password:req.body.password
    });

    req.logIn(user,function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        }else{
            passport.authenticate("local",{failureRedirect:"/login",failureMessage:true})(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
    
});

//---------------------------------------------------- Get -----------------------------------------------------//

app.get("/",function(req,res){
    res.render(__dirname+"/views/home");
});

app.get("/register",function(req,res){
    
    res.render(__dirname+"/views/register");
});

app.get("/login",function(req,res){
    res.render(__dirname+"/views/login");
});

app.get("/secrets", function(req,res){
    console.log(req.isAuthenticated());
    if(req.isAuthenticated()){
        res.render(__dirname+"/views/secrets");
    }else{
        res.redirect("/login");
    }    
});

app.get("/logout",function(req,res){
    req.logOut(function(err){
        if(err){
            console.log(err);
            res.redirect("/secrets");
        }else{
            res.redirect("/");
        }
    })
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/" }), function(req, res){
        res.redirect("/secrets");
});

//---------------------------------------------------- Listen -----------------------------------------------------//

app.listen(3000,function(req,res){
    console.log("Server started on port 3000.");
});