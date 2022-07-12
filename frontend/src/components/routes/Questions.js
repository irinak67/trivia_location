import React from "react";
import { useState, useEffect } from "react";
import axios from "axios";
import { Rating } from "@mui/material";
import { orange } from "@mui/material/colors";
import { Link } from "react-router-dom";
import { useTimer } from "react-timer-hook";
import ChecktheRes from "./Questions";
import { useNavigate } from "react-router";
import { useLocation } from "react-router-dom";
import { Box, Typography, TextField } from "@mui/material";
import io from "socket.io-client";
import useGame from "../hooks/game.hook";
import { API_URL, FRONTEND_URL, USER_STORAGE_KEY } from "../helpers/variables";
import { useTranslation } from "react-i18next";

const socket = io.connect(`${API_URL}`);

//reload=false;
//function Qustion({data:{qustion,correct_answer,incorrect_answers1,incorrect_answers2,incorrect_answers3}}) {
var counter1 = 0;
var counter2 = 0;
var re = 0;
let wa = false;
function Questions() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [resultsList, setResultsList] = useState([]);
  const [timer, setTimer] = useState(
    new Date(new Date().setSeconds(new Date().getSeconds() + 60)).getTime()
  );
  const [loading, setLoading] = useState(true);
  const [isOtherUser, setIsOtherUser] = useState(false);
  const [changeBorders, setChangeBorders] = useState(false);
  const [otherUser, setOtherUser] = useState("");
  const [gameEnded, setGameEnded] = useState(false);
  const [game, setGame] = useState();
  const [wrongAnswer, setWrongAnswer] = useState();
  const [answered, setAnswered] = useState(false);

  const [items, setItems] = useState([
    {
      question: "",
      answer1: "",
      answer2: "",
      answer3: "",
      answer4: "",
      correct_answer: "",
    },
  ]);
  const navigator = useNavigate();
  const location = useLocation();
  const { getGame, answerQues } = useGame();

  const { seconds, minutes, isRunning, start, pause, resume, restart } =
    useTimer({
      expiryTimestamp: timer,
      autoStart: false,
      onExpire: () => onCountDownEnd(),
    });

  const onCountDownEnd = () => {
    if (items.length < 2) {
      socket.emit("game_ended", { _game: game._id });
      return navigate("/ChecktheRes");
    }

    setChangeBorders(false);

    setAnswered(true);
    setTimeout(() => {
      setTimer(
        new Date(new Date().setSeconds(new Date().getSeconds() + 60)).getTime()
      );
      setItems(prevValue => {
        return prevValue.slice(1);
      });
    }, 500);

    // let sendToId = whoToSend();
    // let myResults = JSON.parse(localStorage.getItem("results"));
    // // socket.emit("myResult", { sendToId, myResults });
    // navigate("/ChecktheRes");
  };

  const sendmessage = () => {};
  useEffect(() => {
    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    socket.on(`res_mes`, data => {
      console.log(data, "-----------");
      if (data.items?.length > 0) {
        setChangeBorders(false);
        setTimer(
          new Date(
            new Date().setSeconds(new Date().getSeconds() + 60)
          ).getTime()
        );
        setItems(data.items);
        wa = false;
      } else {
        // navigate("/ChecktheRes");
        // let sendToId = whoToSend();
        // let myResults = JSON.parse(localStorage.getItem("results"));
        // socket.emit("myResult", { sendToId, myResults });
      }
    });

    socket.on(`player_joined_${user.userId}`, data => {
      console.log(data.otherJoined);
      if (data.otherJoined) {
        setOtherUser(data.creator);
      }
      resume();
    });

    socket.on(`wrong_answer_recieved_${user.userId}`, data => {
      if (wa) {
        // setChangeBorders(false);
        setTimeout(() => {
          socket.emit("question_answered", { items: data.slice(1) });
          setChangeBorders(false);
          setAnswered(true);
        }, 2000);
        wa = false;
      } else {
        console.log("HERE!");
        wa = true;
      }
    });

    console.log(user.userId);

    socket.on(`othersResult_${user.userId}`, data => {
      console.log(data, "hit");
    });

    // socket.on("game_ended", () => {
    //   localStorage.setItem("results", JSON.stringify([...resultsList]));
    //   navigator("/ChecktheRes")
    // })
  }, [socket]);

  useEffect(() => {
    console.log(loading, items);
    if (!loading && items.length < 1) {
      localStorage.setItem("game", JSON.stringify({ _game: game._id }));
      navigate("/ChecktheRes");
    }
  }, [items]);

  function increase() {
    // eslint-disable-next-line no-restricted-globals
    re = location.search;
    // alert('re ' + re )
    re++;

    window.location.assign("http://localhost:3000/Questions");
    console.log("re " + re);
    if (re > 5) {
      alert("GAME OVER");
    }
  }

  function reload() {
    alert(` you got ${counter1} coruuct answer and ${counter2}worng answers`);
  }

  // function nextqustion() {
  //   window.location.reload();
  //     }

  //   }

  //Salim
  // //   let c=e.target.value;
  // //  console.log(c);
  //     //const a=e.target.value;
  //     if(e==5){alert("b")}
  //   if(e.target.value=="bill gates" || e.target.value=="1208" ||e.target.value=="Zichron Yaakov"||e.target.value=="1909"||e.target.value=="Sacramento")
  //   {
  //     // alert("ok");
  //     counter1++
  //    // window.location.reload();
  //   //  alert( counter1)
  //   }
  //   else{
  //     // alert("no");
  //    // window.location.reload();
  //     counter2++;
  //   }
  //   // console.log(counter1,counter2);

  //     //       //alert(Object.values(items));
  // //  items.forEach(Element=>{
  // //       console.log(Element.Element);
  // //      })

  // }

  const [item, setItem] = useState({
    question: "",
    answer1: "",
    answer2: "",
    answer3: "",
    answer4: "",
    correct_answer: "",
  });

  function handelChange(event) {
    const { name, value } = event.target;
    setItem(prevInput => {
      return {
        ...prevInput,
        [name]: value,
      };
    });
  }

  useEffect(() => {
    fetch("https://trivianodeserver.herokuapp.com/items")
      .then(res => {
        if (res.ok) {
          return res.json();
        }
      })
      .then(jsonRes => {
        console.log(jsonRes);
        setItems(jsonRes);
      })
      .catch(err => console.log(err));

    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    if (!user) {
      alert("Please login to play!");
      return window.location.replace(`${FRONTEND_URL}/Registration`);
    }
    getCurrentGame(user);

    socket.emit("connected", { user_id: user.userId });
  }, []);

  const getCurrentGame = async user => {
    let _game =
      location.pathname.split("/")[location.pathname.split("/").length - 1];

    const { game } = await getGame(_game);
    if (game) {
      console.log(game);
      if (game.gameType === "single_player") {
        if (user.userId === game.creator._user._id) start();
        else {
          alert("Access Denied!");
          return navigate("/");
        }
      } else {
        // if (user.userId !== game.creator._user._id) {
        // }
      }
      setGame(game);
      if (game.finished) setGameEnded(true);
    }
    setLoading(false);
  };

  //  function Additem(event){
  //    event.preventDefault();
  //    const newItem={
  //      qustion:item.qustion,
  //     option1:item.option1,
  //      option2:item.option2,
  //       option3:item.option3,

  //      option4:item.option4,

  //  }
  //  axios.post("http://localhost:3001/newitem",newItem);
  //  console.log("newitem")
  //  alert('item added');

  //  setItem({
  //    answer:"",
  //     option1:"",
  //     option2:"",
  //     option3:"",
  //     option4:"",
  //    });
  //  }

  const [qoust, setqutes] = useState("");

  const getqute = () => {
    fetch(`${API_URL}/items`)
      .then(res => res.json())
      .then(data => {
        //let randomnum=Math.floor(Math.random()*data.length);
        setqutes(data);
      });
  };

  function fifty() {}

  const whoToSend = () => {
    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    let sendToId = "";
    if (user.userId === game.creator._user._id) {
      sendToId = game.otherPlayer._user._id;
    } else {
      sendToId = game.creator._user._id;
    }

    return sendToId;
  };

  async function answers(answer, question) {
    if (!isRunning) return;
    const remainingTime = minutes == 1 ? 60 : seconds;
    const obj = {
      question: question,
      answer: answer,
      correct_answer: items[0].correct_answer,
      remainingTime,
    };

    const { answered } = await answerQues(game._id, obj, remainingTime);
    if (!answered) {
      let unanswered = items.filter(q => q.question !== question);
      setAnswered(true);
      setTimeout(() => {
        setTimer(
          new Date(
            new Date().setSeconds(new Date().getSeconds() + 60)
          ).getTime()
        );
      }, 500);

      return setItems([...unanswered]);
    }

    // return;
    setResultsList(prevValue => {
      return [...prevValue, obj];
    });

    console.log("I am here!");
    // socket.emit("question_answered",{answer});
    setChangeBorders(true);

    console.log(items, "----");

    if (items.length > 1) {
      // if (answer !== items[0].correct_answer) {
      // wa = true;
      // const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
      // let sendToId = whoToSend();
      // console.log("hree!");

      // socket.emit("wrong_answer", { sendToId, items });
      // } else {
      // wa = true;
      console.log(items);
      setAnswered(true);

      setTimeout(() => {
        setChangeBorders(false);
        // socket.emit("question_answered", { items: items.slice(1) });
        setItems(prevValue => {
          return prevValue.slice(1);
        });
        setTimer(
          new Date(
            new Date().setSeconds(new Date().getSeconds() + 60)
          ).getTime()
        );
      }, 1000);
      // }
    } else {
      console.log("-------");

      // let sendToId = whoToSend();
      // let myResults = JSON.parse(localStorage.getItem("results"));
      // socket.emit("myResult", { sendToId, myResults });
      socket.emit("game_ended", { _game: game._id });

      // socket.emit("question_answered", { items: items.slice(1) });
      navigator("/ChecktheRes");

      // socket.emit("game_ended");
    }

    localStorage.setItem("results", JSON.stringify([...resultsList, obj]));
    localStorage.setItem("game", JSON.stringify({ _game: game._id }));

    console.log(resultsList);
  }

  useEffect(() => {
    if (answered) restart(timer, true);
  }, [timer]);

  useEffect(() => {
    if (game) {
      console.log(game.otherPlayers.length);
      const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
      if (user.userId === game.creator._user._id) setIsOtherUser(false);
      else if (game.otherPlayers.length === 1) {
        setIsOtherUser(true);
        socket.emit("user_joined", {
          creator: user.userId,
          _game: game._id,
        });
      } else {
        navigate("/joinGame", {
          state: {
            url: `${FRONTEND_URL}/game/${game._id}`,
          },
        });
      }
    }
  }, [game]);

  const [color, setColor] = useState("orange");

  const formatTimer = timeUnit => `${timeUnit < 10 ? "0" : ""}${timeUnit}`;

  return (
    <>
      {loading || game.finished ? (
        <div className='loaderBox'>
          <h1>{loading ? "Loading..." : "Game ended!"} </h1>
        </div>
      ) : (
        <div className='container'>
          <div className='qustionClass'>
            <h1>
              {formatTimer(minutes)}:{formatTimer(seconds)}
            </h1>

            {/* <h1>{qoust.text}</h1> */}
            {/* <input onChange={handelChange} name="qustion" value={item.qustion} placeholder="qustion"></input>
          <input onChange={handelChange} name="option1" value={item.option1} placeholder="option1"></input>
          <input onChange={handelChange} name="option2" value={item.option2} placeholder="option2"></input>
          <input onChange={handelChange} name="option3" value={item.option3} placeholder="option3"></input>
          <input onChange={handelChange} name="option4" value={item.option4} placeholder="option4"></input>
  
          <input onChange={handelChange} name="description" value={item.description}  placeholder="description"></input>
          <input onChange={handelChange} name="qustion" value={item.qustion}  placeholder="qustion"></input> */}
            {/* <button onClick={Additem}>Additem</button> */}

            {/* <button onClick={getqute}>get items</button>  */}
          </div>

          <Box className='questions main'>
            <Typography
              className='questionTitle'
              sx={{ fontWeight: "bold", fontSize: 52, color: "#0E3B7F" }}
            >
              {t(items[0]?.question)}
            </Typography>

            <button
              id='1'
              className='normal-button'
              value={items[0]?.answer1}
              style={{
                backgroundColor: !changeBorders
                  ? "#FFFDE7"
                  : items[0]?.answer1 === items[0]?.correct_answer
                  ? "green"
                  : "red",
                color: !changeBorders
                  ? "black"
                  : items[0]?.answer1 === items[0]?.correct_answer && "white",
              }}
              onClick={e => answers(e.target.value, items[0]?.question)}
            >
              {items[0]?.answer1}
            </button>
            <button
              id='2'
              className='normal-button'
              value={items[0]?.answer2}
              onClick={e => answers(e.target.value, items[0]?.question)}
              style={{
                backgroundColor: !changeBorders
                  ? "#FFFDE7"
                  : items[0]?.answer2 === items[0]?.correct_answer
                  ? "green"
                  : "red",
                color: !changeBorders
                  ? "black"
                  : items[0]?.answer2 === items[0]?.correct_answer && "white",
              }}
            >
              {items[0]?.answer2}
            </button>
            {/* <button 
                onClick={increase}  
                className='button'
              >
                next question
              </button>       */}

            <button
              id='3'
              value={items[0]?.answer3}
              onClick={e => answers(e.target.value, items[0]?.question)}
              className='normal-button'
              style={{
                backgroundColor: !changeBorders
                  ? "#FFFDE7"
                  : items[0]?.answer3 === items[0]?.correct_answer
                  ? "green"
                  : "red",
                color: !changeBorders
                  ? "black"
                  : items[0]?.answer3 === items[0]?.correct_answer && "white",
              }}
            >
              {items[0]?.answer3}
            </button>
            <button
              id='4'
              value={items[0]?.answer4}
              onClick={e => answers(e.target.value, items[0]?.question)}
              className='normal-button'
              style={{
                backgroundColor: !changeBorders
                  ? "#FFFDE7"
                  : items[0]?.answer4 === items[0]?.correct_answer
                  ? "green"
                  : "red",
                color: !changeBorders
                  ? "black"
                  : items[0]?.answer4 === items[0]?.correct_answer && "white",
              }}
            >
              {items[0]?.answer4}
            </button>
            {/* <button 
                 onClick={reload}  
                className='button'
              ><Link  to={"/ChecktheRes"} >
              {("check the result")}
            </Link>
                
              </button>                */}
          </Box>
        </div>
      )}
    </>
  );
}

export default Questions;
