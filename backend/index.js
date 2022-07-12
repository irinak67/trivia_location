// const questionRouter = require('./routers/questions.router') 
 
const express = require("express"); 
const app = express(); 
const cors = require("cors"); 
app.use(cors()); 
app.options("*", cors()); 
const http = require("http"); 
const server = http.createServer(app); 
const { Server } = require("socket.io"); 
const io = new Server(server, { 
  cors: { 
    origin: "*", 
    methods: ["GET", "POST"], 
  }, 
}); 
const port = process.env.PORT || 3500; 
require("dotenv").config(); 
 
const { json } = require("express"); 
 
const mongoose = require("mongoose"); 
const Game = require("./models/Game"); 
 
app.use(express.json()); 
app.use(express.urlencoded({ extended: false })); 
 
app.use("/api/auth", require("./routers/auth.router")); 
app.use("/game", require("./routers/game")); 
 
async function start() { 
  try { 
    await mongoose 
      .connect( 
        "mongodb+srv://salim:salim@cluster0.idfuq.mongodb.net/newitemsDB?retryWrites=true&w=majority" 
      )  
      .then(() => { 
        console.log("connected to MongoDB..."); 
      }) 
      .catch(err => { 
        console.log("Could not connect to Mongodb", err); 
      }); 
 
    // app.listen(port, () => console.log(`Listening on port ${port}`)); 
  } catch (e) { 
    console.log("Server Error", e.message); 
    process.exitCode(1); 
  } 
} 
 
const itemSchema = { 
  id: String, 
  question: String, 
  answer1: String, 
  answer2: String, 
  answer3: String, 
  answer4: String, 
  correct_answer: String, 
}; 
const Item = mongoose.model("Item", itemSchema); 
console.log(itemSchema); 
 
const itemSchema1 = { 
  question: String, 
  answer1: String, 
  answer2: String, 
  answer3: String, 
  answer4: String, 
  correct_answer: String, 
}; 
const Item1 = mongoose.model("Item1", itemSchema1); 
console.log(itemSchema1); 
 
app.get("/items", (req, res) => { 
  Item.find() 
    .then(items => res.json(items)) 
    .catch(err => res.status(400).json("Error: " + err));  
}); 
 
console.log(itemSchema); 
 
app.get("/item1", (req, res) => { 
  Item1.find() 
    .then(items => res.json(items)) 
    .catch(err => res.status(400).json("Error: " + err)); 
}); 
console.log(itemSchema1); 
 
app.post("/newitem", (req, res) => { 
  const newItem = new Item({ 
    answer: req.body.answer, 
    option1: req.body.option1, 
    option2: req.body.option2, 
    option3: req.body.option3, 
    option4: req.body.option4, 
  }); 
  newItem 
    .save() 
    .then(item => console.log(item)) 
    .catch(err => res.status(400).json("Error" + err)); 
}); 
 
 
let usersConnected = {}; 
 
io.on("connection", socket => { 
  socket.on("connected", data => { 
    const { user_id } = data; 
    usersConnected[user_id] = socket.id; 
    console.log(usersConnected); 
  }); 
 
  socket.on("question_answered", data => { 
    socket.broadcast.emit("res_mes", data); 
  }); 
  socket.on("wrong_answer", ({ sendToId, items }) => { 
    console.log(sendToId, "-----"); 
    io.to(usersConnected[sendToId]).emit( 
      `wrong_answer_recieved_${sendToId}`, 
      items 
    ); 
  }); 
  socket.on("myResult", data => { 
    console.log(data, "hit"); 
    socket.emit(`othersResult_${data.sendToId}`, { 
      otherResults: data.myResults, 
    });  
  }); 
  socket.on("user_joined", async data => { 
    const game = await Game.findById(data._game); 
 
    console.log(game); 
 
    console.log("HAHA!"); 
    let users = [game.creator._user]; 
 
    game.otherPlayers.forEach(player => { 
      users.push(player._user); 
    }); 
 
    console.log(users); 
    users.forEach(player => { 
      io.to(usersConnected[player.toString()]).emit( 
        `player_joined_${player.toString()}`, 
        { ...data } 
      ); 
    }); 
  }); 
 
  socket.on("game_ended", async ({ _game }) => { 
    const game = await Game.findById(_game) 
      .populate({ 
        model: "User", 
        path: "creator._user", 
      }) 
      .populate({ 
        model: "User", 
        path: "otherPlayers._user", 
      }); 
 
    console.log(game); 
    let users = [game.creator._user._id]; 
 
    game.otherPlayers.forEach(player => { 
      users.push(player._user._id); 
    }); 
 
    console.log(users); 
 
    users.forEach(player => { 
      io.to(usersConnected[player.toString()]).emit( 
        `game_ended_${player.toString()}`, 
        { game } 
      ); 
 
      console.log("Its a hit Initially!", `game_ended_${player.toString()}`); 
    }); 
  }); 
}); 
 
server.listen(port, () => { 
  console.log("socket is running"); 
}); 
 
start(); 
 