// script.js
const menuToggle = document.querySelector('.menu-toggle');
const dashboard = document.querySelector('.dashboard');
const container = document.querySelector('.container');

menuToggle.addEventListener('click', () => {
    dashboard.classList.toggle('open');
    container.classList.toggle('menu-open');
});