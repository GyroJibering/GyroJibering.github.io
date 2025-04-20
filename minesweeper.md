---
layout: default
title: Minesweeper
permalink: /minesweeper/
---

<div class="profile-container">
  <div class="profile-navigation">
    <a href="/about/" class="profile-button">记忆配对</a>
    <a href="/minesweeper/" class="profile-button active">扫雷游戏</a>
    <a href="/number-maze/" class="profile-button">数字迷宫</a>
  </div>

  <div class="game-container">
    <h1>扫雷游戏</h1>
    <div class="game-info">
      <div class="mines">剩余雷数: <span id="mines">10</span></div>
      <div class="timer">用时: <span id="timer">0</span>秒</div>
    </div>
    <div class="game-controls">
      <button id="startGame" class="game-button">新游戏</button>
      <select id="difficulty" class="game-select">
        <option value="easy">简单 (10个雷)</option>
        <option value="medium">中等 (20个雷)</option>
        <option value="hard">困难 (30个雷)</option>
      </select>
    </div>
    <div class="game-board" id="gameBoard"></div>
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

.game-controls {
  display: flex;
  justify-content: center;
  gap: 1rem;
  margin: 1rem 0;
}

.game-button {
  padding: 0.5rem 1rem;
  font-size: 1.2rem;
  background-color: #228be6;
  color: white;
  border: none;
  border-radius: 0.25rem;
  cursor: pointer;
  transition: all 0.2s ease;
}

.game-button:hover {
  background-color: #1c7ed6;
  transform: translateY(-2px);
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.game-button:active {
  transform: translateY(0);
  box-shadow: none;
}

.game-select {
  padding: 0.5rem;
  font-size: 1.2rem;
  border: 1px solid #e9ecef;
  border-radius: 0.25rem;
  background-color: white;
  color: #495057;
}

.game-board {
  display: grid;
  grid-template-columns: repeat(10, 1fr);
  gap: 2px;
  margin: 2rem auto;
  max-width: 500px;
  background-color: #e9ecef;
  padding: 2px;
  border-radius: 0.25rem;
}

.cell {
  aspect-ratio: 1;
  background-color: #f8f9fa;
  border: 1px solid #e9ecef;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.2rem;
  cursor: pointer;
  user-select: none;
  transition: background-color 0.2s ease;
}

.cell:hover {
  background-color: #e9ecef;
}

.cell.revealed {
  background-color: #dee2e6;
  cursor: default;
}

.cell.mine {
  background-color: #fa5252;
  color: white;
}

.cell.flagged {
  background-color: #fff3bf;
}

.cell.flagged::after {
  content: '🚩';
}

.cell[data-count="1"] { color: #228be6; }
.cell[data-count="2"] { color: #40c057; }
.cell[data-count="3"] { color: #fa5252; }
.cell[data-count="4"] { color: #7950f2; }
.cell[data-count="5"] { color: #fd7e14; }
.cell[data-count="6"] { color: #15aabf; }
.cell[data-count="7"] { color: #212529; }
.cell[data-count="8"] { color: #868e96; }
</style>

<script>
const BOARD_SIZE = 10;
const MINE_COUNTS = {
  easy: 10,
  medium: 20,
  hard: 30
};

let board = [];
let mines = [];
let revealed = 0;
let flagged = 0;
let gameOver = false;
let timer = 0;
let timerInterval;

function createBoard() {
  const gameBoard = document.getElementById('gameBoard');
  gameBoard.innerHTML = '';
  board = [];
  mines = [];
  revealed = 0;
  flagged = 0;
  gameOver = false;
  clearInterval(timerInterval);
  timer = 0;
  document.getElementById('timer').textContent = '0';
  
  const mineCount = MINE_COUNTS[document.getElementById('difficulty').value];
  document.getElementById('mines').textContent = mineCount;
  
  // Initialize board
  for (let i = 0; i < BOARD_SIZE; i++) {
    board[i] = [];
    for (let j = 0; j < BOARD_SIZE; j++) {
      const cell = document.createElement('div');
      cell.className = 'cell';
      cell.dataset.row = i;
      cell.dataset.col = j;
      cell.addEventListener('click', () => revealCell(i, j));
      cell.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        flagCell(i, j);
      });
      gameBoard.appendChild(cell);
      board[i][j] = { revealed: false, mine: false, flagged: false, count: 0 };
    }
  }
  
  // Place mines
  let minesPlaced = 0;
  while (minesPlaced < mineCount) {
    const row = Math.floor(Math.random() * BOARD_SIZE);
    const col = Math.floor(Math.random() * BOARD_SIZE);
    if (!board[row][col].mine) {
      board[row][col].mine = true;
      mines.push([row, col]);
      minesPlaced++;
    }
  }
  
  // Calculate adjacent mines
  for (let i = 0; i < BOARD_SIZE; i++) {
    for (let j = 0; j < BOARD_SIZE; j++) {
      if (!board[i][j].mine) {
        let count = 0;
        for (let di = -1; di <= 1; di++) {
          for (let dj = -1; dj <= 1; dj++) {
            const ni = i + di;
            const nj = j + dj;
            if (ni >= 0 && ni < BOARD_SIZE && nj >= 0 && nj < BOARD_SIZE && board[ni][nj].mine) {
              count++;
            }
          }
        }
        board[i][j].count = count;
      }
    }
  }
  
  // Start timer
  timerInterval = setInterval(() => {
    timer++;
    document.getElementById('timer').textContent = timer;
  }, 1000);
}

function revealCell(row, col) {
  if (gameOver || board[row][col].revealed || board[row][col].flagged) return;
  
  const cell = document.querySelector(`.cell[data-row="${row}"][data-col="${col}"]`);
  board[row][col].revealed = true;
  cell.classList.add('revealed');
  
  if (board[row][col].mine) {
    cell.classList.add('mine');
    cell.textContent = '💣';
    gameOver = true;
    revealAllMines();
    clearInterval(timerInterval);
    setTimeout(() => alert('游戏结束！'), 100);
    return;
  }
  
  revealed++;
  if (board[row][col].count > 0) {
    cell.textContent = board[row][col].count;
    cell.dataset.count = board[row][col].count;
  } else {
    // Reveal adjacent cells
    for (let di = -1; di <= 1; di++) {
      for (let dj = -1; dj <= 1; dj++) {
        const ni = row + di;
        const nj = col + dj;
        if (ni >= 0 && ni < BOARD_SIZE && nj >= 0 && nj < BOARD_SIZE) {
          revealCell(ni, nj);
        }
      }
    }
  }
  
  if (revealed === BOARD_SIZE * BOARD_SIZE - mines.length) {
    gameOver = true;
    clearInterval(timerInterval);
    setTimeout(() => alert(`恭喜你赢了！用时 ${timer} 秒！`), 100);
  }
}

function flagCell(row, col) {
  if (gameOver || board[row][col].revealed) return;
  
  const cell = document.querySelector(`.cell[data-row="${row}"][data-col="${col}"]`);
  if (board[row][col].flagged) {
    board[row][col].flagged = false;
    cell.classList.remove('flagged');
    flagged--;
  } else {
    board[row][col].flagged = true;
    cell.classList.add('flagged');
    flagged++;
  }
  document.getElementById('mines').textContent = mines.length - flagged;
}

function revealAllMines() {
  mines.forEach(([row, col]) => {
    const cell = document.querySelector(`.cell[data-row="${row}"][data-col="${col}"]`);
    cell.classList.add('mine');
    cell.textContent = '💣';
  });
}

document.getElementById('startGame').addEventListener('click', createBoard);
document.getElementById('difficulty').addEventListener('change', createBoard);

// Start initial game
createBoard();
</script> 