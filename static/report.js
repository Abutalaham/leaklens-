"use strict";

const toggle = document.querySelector("#theme-toggle");
const storedTheme = localStorage.getItem("leaklens_theme");
const initialTheme = storedTheme === "light" || storedTheme === "dark" ? storedTheme : "dark";

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  toggle.textContent = theme === "dark" ? "☼" : "☾";
  toggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} theme`);
  toggle.title = `Switch to ${theme === "dark" ? "light" : "dark"} theme`;
}

setTheme(initialTheme);
toggle.addEventListener("click", () => {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("leaklens_theme", nextTheme);
  setTheme(nextTheme);
});
