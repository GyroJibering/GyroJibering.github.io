---
layout: page
title: 扫雷游戏
permalink: /minesweeper/
---

<section class="profile-content">
  <div class="profile-content__panel">
    <div class="profile-section">
      <h2 class="profile-section__title">游戏导航</h2>
      <div class="profile-section__content">
        <div class="game-navigation">
          <a href="/about/" class="game-nav-btn">记忆配对</a>
          <a href="/minesweeper/" class="game-nav-btn active">扫雷游戏</a>
          <a href="/number-maze/" class="game-nav-btn">数字迷宫</a>
          <a href="/dinosaur/" class="game-nav-btn">小恐龙</a>
        </div>
      </div>
    </div>

    <div class="profile-section">
      <h2 class="profile-section__title">扫雷游戏</h2>
      <div class="profile-section__content">
        <div class="game-container">
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
    </div>
  </div>
</section>

<style>
.game-navigation {
  display: flex;
  justify-content: center;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.game-nav-btn {
  padding: 0.5rem 1rem;
  font-size: 1rem;
  background-color: rgba(255, 255, 255, .6);
  color: #495057;
  border: 1px solid rgba(0, 0, 0, .1);
  border-radius: calc(var(--border-radius) * 1.5);
  text-decoration: none;
  transition: transform .3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow .3s cubic-bezier(0.4, 0, 0.2, 1), background .3s ease, color .3s ease;
  font-weight: 500;
}

.game-nav-btn:hover {
  background-color: rgba(34, 139, 230, .1);
  transform: translateY(-3px);
  box-shadow: 0 4px 12px rgba(34, 139, 230, .2);
}

.game-nav-btn.active {
  background-color: var(--link-color);
  color: white;
  border-color: var(--link-color);
}

.game-container {
  text-align: center;
  padding: 1rem 0;
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
  padding: 0.75rem 1.5rem;
  font-size: 1.1rem;
  font-weight: 600;
  background-color: var(--link-color);
  color: white;
  border: none;
  border-radius: calc(var(--border-radius) * 1.5);
  cursor: pointer;
  transition: transform .3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow .3s cubic-bezier(0.4, 0, 0.2, 1);
}

.game-button:hover {
  background-color: var(--link-hover-color);
  transform: translateY(-4px);
  box-shadow: 0 8px 20px rgba(34, 139, 230, .3);
}

.game-button:active {
  transform: translateY(-2px);
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