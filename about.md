---
layout: default
title: Memory Match Game
permalink: /about/
---

<div class="profile-container">
  <div class="profile-navigation">
    <a href="/about/" class="profile-button active">记忆配对</a>
    <a href="/minesweeper/" class="profile-button">扫雷游戏</a>
    <a href="/number-maze/" class="profile-button">数字迷宫</a>
  </div>

  <div class="game-container">
    <h1>记忆配对游戏</h1>
    <div class="game-info">
      <div class="moves">移动次数: <span id="moves">0</span></div>
      <div class="timer">用时: <span id="timer">0</span>秒</div>
    </div>
    <div class="game-board" id="gameBoard"></div>
    <button id="startGame" class="start-button">开始游戏</button>
  </div>
</div>

<style>
.profile-container {
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
}

.profile-navigation {
  display: flex;
  justify-content: center;
  gap: 1rem;
  margin-bottom: 2rem;
}

.profile-button {
  padding: 0.5rem 1rem;
  font-size: 1.2rem;
  background-color: #f8f9fa;
  color: #495057;
  border: 1px solid #e9ecef;
  border-radius: 0.25rem;
  text-decoration: none;
  transition: all 0.2s ease;
}

.profile-button:hover {
  background-color: #e9ecef;
  transform: translateY(-2px);
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.profile-button.active {
  background-color: #228be6;
  color: white;
  border-color: #228be6;
}

.game-container {
  text-align: center;
}

.game-info {
  display: flex;
  justify-content: space-between;
  margin: 1rem 0;
  font-size: 1.2rem;
  color: #495057;
}

.game-board {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin: 2rem 0;
  perspective: 1000px;
}

.card {
  aspect-ratio: 1;
  position: relative;
  transform-style: preserve-3d;
  transition: transform 0.6s;
  cursor: pointer;
}

.card-inner {
  position: relative;
  width: 100%;
  height: 100%;
  text-align: center;
  transition: transform 0.6s;
  transform-style: preserve-3d;
}

.card-front, .card-back {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden;
  border-radius: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2rem;
}

.card-front {
  background-color: #e9ecef;
}

.card-back {
  background-color: #228be6;
  color: white;
  transform: rotateY(180deg);
}

.card.flipped .card-inner {
  transform: rotateY(180deg);
}

.card.matched .card-inner {
  transform: rotateY(180deg);
}

.card.matched .card-back {
  background-color: #40c057;
}

.start-button {
  padding: 0.5rem 1rem;
  font-size: 1.2rem;
  background-color: #228be6;
  color: white;
  border: none;
  border-radius: 0.25rem;
  cursor: pointer;
  transition: all 0.2s ease;
}

.start-button:hover {
  background-color: #1c7ed6;
  transform: translateY(-2px);
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.start-button:active {
  transform: translateY(0);
  box-shadow: none;
}
</style>

<script>
const emojis = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼'];
const cards = [...emojis, ...emojis];
let flippedCards = [];
let matchedPairs = 0;
let moves = 0;
let timer = 0;
let timerInterval;
let gameStarted = false;
let canFlip = true;

function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function createCard(emoji) {
  const card = document.createElement('div');
  card.className = 'card';
  
  const cardInner = document.createElement('div');
  cardInner.className = 'card-inner';
  
  const cardFront = document.createElement('div');
  cardFront.className = 'card-front';
  
  const cardBack = document.createElement('div');
  cardBack.className = 'card-back';
  cardBack.textContent = emoji;
  
  cardInner.appendChild(cardFront);
  cardInner.appendChild(cardBack);
  card.appendChild(cardInner);
  
  card.addEventListener('click', () => flipCard(card));
  return card;
}

function flipCard(card) {
  if (!gameStarted || !canFlip) return;
  if (flippedCards.length < 2 && !card.classList.contains('flipped') && !card.classList.contains('matched')) {
    card.classList.add('flipped');
    flippedCards.push(card);

    if (flippedCards.length === 2) {
      canFlip = false;
      moves++;
      document.getElementById('moves').textContent = moves;
      
      const [card1, card2] = flippedCards;
      if (card1.querySelector('.card-back').textContent === card2.querySelector('.card-back').textContent) {
        card1.classList.add('matched');
        card2.classList.add('matched');
        matchedPairs++;
        
        if (matchedPairs === emojis.length) {
          clearInterval(timerInterval);
          setTimeout(() => {
            alert(`恭喜你赢了！用时 ${timer} 秒，移动 ${moves} 次！`);
          }, 500);
        }
        canFlip = true;
      } else {
        setTimeout(() => {
          card1.classList.remove('flipped');
          card2.classList.remove('flipped');
          canFlip = true;
        }, 1000);
      }
      flippedCards = [];
    }
  }
}

function startGame() {
  if (gameStarted) return;
  gameStarted = true;
  const gameBoard = document.getElementById('gameBoard');
  gameBoard.innerHTML = '';
  matchedPairs = 0;
  moves = 0;
  timer = 0;
  document.getElementById('moves').textContent = '0';
  document.getElementById('timer').textContent = '0';
  
  const shuffledCards = shuffle([...cards]);
  shuffledCards.forEach(emoji => {
    gameBoard.appendChild(createCard(emoji));
  });

  timerInterval = setInterval(() => {
    timer++;
    document.getElementById('timer').textContent = timer;
  }, 1000);
}

document.getElementById('startGame').addEventListener('click', startGame);
</script>

