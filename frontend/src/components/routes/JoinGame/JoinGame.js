import { Button } from "@mui/material";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router-dom";
import useGame from "../../hooks/game.hook";
import "./joinGame.css";

const JoinGame = () => {
  const { t } = useTranslation();
  const { joinGame } = useGame();
  const navigate = useNavigate();
  const location = useLocation();

  const [name, setName] = useState("");
  const [link, setLink] = useState("");

  useEffect(() => {
    if (location.state && location.state.url) setLink(location.state.url);
  }, []);

  const changeHandler = e => {
    const { name, value } = e.target;

    switch (name) {
      case "name":
        return setName(value);

      case "link":
        return setLink(value);

      default:
        break;
    }
  };

  const handleSubmit = async () => {
    console.log(link);
    if (!link || !name) return alert("Please fill the form correctly!");
    const splittedLink = link.split("/");

    const _game = splittedLink[splittedLink.length - 1];

    const { game } = await joinGame(_game, name);
    if (game) {
      navigate(`/game/${_game}`);
    }
  };
  return (
    <div className='joinGame'>
      <div className='joinGame__Form'>
        <h1>Join Game</h1>
        <input
          type='text'
          placeholder='Enter your name'
          className='cusInput'
          style={{ marginTop: "-0.5rem" }}
          name='name'
          value={name}
          onChange={changeHandler}
        />
        <input
          type='text'
          placeholder='Enter game link'
          className='cusInput'
          name='link'
          value={link}
          onChange={changeHandler}
        />
        <div className='centerMyContent'>
          <Button className='smallBtn' onClick={handleSubmit}>
            {t("Enter Game")}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default JoinGame;
