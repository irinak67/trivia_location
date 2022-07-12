import React from "react";
import LanguageFlags from "../multilanguage/languageFlags";
import { useTranslation } from "react-i18next";
import "./header.css";

export default function HeaderContent() {
  const { t } = useTranslation(); //translation

  return (
    <div className='header' style={{ position: "relative" }}>
      <a href='/' style={{ display: "block", height: "100%", width: "100%" }} />
      <div style={{ position: "absolute", top: "20px", right: "20px" }}>
        <LanguageFlags />
      </div>
    </div>
  );
}
