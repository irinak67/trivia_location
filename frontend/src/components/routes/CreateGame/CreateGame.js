import { Button, Box, Modal, TextField } from "@mui/material";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import {
  USER_STORAGE_KEY,
  API_URL,
  FRONTEND_URL,
} from "../../helpers/variables";
import useGame from "../../hooks/game.hook";

const CreateGame = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [modalOpen, setModalOpen] = useState(false);
  const [url, setUrl] = useState();

  const openModal = () => setModalOpen(true);
  return (
    <div>
      <div className='create-game'>
        <Button className='button-med' onClick={openModal}>
          <h2>{t("Create Game")}</h2>
        </Button>
        <Button
          className='button-med margin-left-med'
          onClick={() => navigate("/joinGame")}
        >
          <h2>{t("Join Game")}</h2>
        </Button>
        <NameModal open={modalOpen} setOpen={setModalOpen} />
      </div>
      {/* <div>
        <Button className='button-med' onClick={() => navigate("/joinGame")}>
          <h2>{t("Single Player")}</h2>
        </Button>
        <Button
          className='button-med margin-left-med'
          onClick={() => navigate("/joinGame")}
        >
          <h2>{t("Multi Player")}</h2>
        </Button>
        <TextField
          id='standard-basic'
          name='Link'
          type='text'
          label={t("Your Game")}
          variant='outlined'
          margin='normal'
          required
          value={url}
        />
      </div> */}
    </div>
  );
};

const NameModal = ({ open, setOpen }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { createGame } = useGame();
  const [name, setName] = useState("");
  const [gameType, setGameType] = useState("");

  const handleSubmit = async () => {
    if (!name || !gameType) return alert("Please fill the form correctly!");
    const user = JSON.parse(localStorage.getItem(USER_STORAGE_KEY));
    const { game } = await createGame(name, gameType, user.userId);
    if (game) {
      console.log(game.gameType);

      if (game.gameType === "multi_player") {
        let linkToGame = `${FRONTEND_URL}/game/${game._id}`;
        navigator.clipboard.writeText(linkToGame);
        alert("Link copied to clipboard!");
      }

      navigate(`/game/${game._id}`);
      // console.log(game);
      console.log(`/game/${game._id}`);
    }
  };

  const handleClose = () => setOpen(false);
  return (
    <Modal
      open={open}
      onClose={handleClose}
      aria-labelledby='modal-modal-title'
      aria-describedby='modal-modal-description'
    >
      <Box sx={style} className='modalName-box'>
        <label htmlFor='creator_name'>Enter your name</label>
        <input
          type='text'
          id='creator_name'
          name='creator_name'
          placeholder='Enter your name'
          onChange={e => setName(e.target.value)}
        />

        <div className='modalName-box-radio'>
          <input
            type='radio'
            id='single_player'
            name='game_type'
            value='single_player'
            onChange={e => setGameType(e.target.value)}
          />
          <label htmlFor='single_player'>Single Player</label>
          <br />
          <input
            type='radio'
            id='multi_player'
            name='game_type'
            value='multi_player'
            onChange={e => setGameType(e.target.value)}
          />
          <label for='css'>Multiplayer</label>
          <br />
        </div>

        <div className='centerMyContent'>
          <Button className='smallBtn' onClick={handleSubmit}>
            {t("Submit")}
          </Button>
        </div>
      </Box>
    </Modal>
  );
};

const style = {
  position: "absolute",
  top: "50%",
  left: "50%",
  transform: "translate(-50%, -50%)",
  width: 400,
  bgcolor: "background.paper",
  boxShadow: 24,
  borderRadius: "1rem",
  p: 4,
};

export default CreateGame;
