---
layout: page
title: 数字迷宫
permalink: /number-maze/
---

<section class="profile-content">
  <div class="profile-content__panel">
    <div class="profile-section">
      <h2 class="profile-section__title">游戏导航</h2>
      <div class="profile-section__content">
        <div class="game-navigation">
          <a href="/about/" class="game-nav-btn">记忆配对</a>
          <a href="/minesweeper/" class="game-nav-btn">扫雷游戏</a>
          <a href="/number-maze/" class="game-nav-btn active">数字迷宫</a>
          <a href="/dinosaur/" class="game-nav-btn">小恐龙</a>
          <a href="http://114.55.15.44:8080/" class="game-nav-btn" target="_blank">战争模拟</a>
        </div>
      </div>
    </div>

    <div class="profile-section">
      <h2 class="profile-section__title">数字迷宫</h2>
      <div class="profile-section__content">
        <div class="game-container">
    <div class="game-info">
      <div class="level">关卡: <span id="level">1</span></div>
      <div class="timer">剩余时间: <span id="timer">30</span>秒</div>
      <div class="score">得分: <span id="score">0</span></div>
    </div>
    <div class="game-controls">
      <button id="startGame" class="game-button">开始游戏</button>
      <select id="difficulty" class="game-select">
        <option value="easy">简单 (30秒)</option>
        <option value="medium">中等 (20秒)</option>
        <option value="hard">困难 (15秒)</option>
      </select>
    </div>
    <div class="game-phase" id="memoryPhase">
      <h2>记忆阶段</h2>
      <div class="number-display" id="numberDisplay"></div>
    </div>
          <div class="game-phase" id="mazePhase" style="display: none;">
            <h2>迷宫阶段</h2>
            <div class="maze-container" id="mazeContainer"></div>
          </div>
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

.game-phase {
  margin: 2rem 0;
}

.number-display {
  font-size: 3rem;
  font-weight: bold;
  color: #228be6;
  margin: 2rem 0;
  min-height: 4rem;
}

.maze-container {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 0.5rem;
  margin: 2rem auto;
  max-width: 500px;
}

.maze-cell {
  aspect-ratio: 1;
  background-color: #f8f9fa;
  border: 2px solid #e9ecef;
  border-radius: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  font-weight: bold;
  cursor: pointer;
  transition: all 0.2s ease;
}

.maze-cell:hover {
  background-color: #e9ecef;
  transform: scale(1.05);
}

.maze-cell.selected {
  background-color: #228be6;
  color: white;
  border-color: #228be6;
}

.maze-cell.correct {
  background-color: #40c057;
  color: white;
  border-color: #40c057;
}

.maze-cell.wrong {
  background-color: #fa5252;
  color: white;
  border-color: #fa5252;
}

@keyframes pulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.1); }
  100% { transform: scale(1); }
}

.pulse {
  animation: pulse 1s infinite;
}
</style>

<script>
const DIFFICULTY_TIMES = {
  easy: 30,
  medium: 20,
  hard: 15
};

let currentLevel = 1;
let targetSequence = [];
let selectedSequence = [];
let gameStarted = false;
let timer = 0;
let timerInterval;
let score = 0;
let memoryPhase = true;

function generateSequence(length) {
  const sequence = [];
  for (let i = 0; i < length; i++) {
    sequence.push(Math.floor(Math.random() * 9) + 1);
  }
  return sequence;
}

function createMaze() {
  const mazeContainer = document.getElementById('mazeContainer');
  mazeContainer.innerHTML = '';
  
  for (let i = 1; i <= 25; i++) {
    const cell = document.createElement('div');
    cell.className = 'maze-cell';
    cell.textContent = i;
    cell.dataset.value = i;
    cell.addEventListener('click', () => selectCell(cell));
    mazeContainer.appendChild(cell);
  }
}

function selectCell(cell) {
  if (!gameStarted || memoryPhase) return;
  
  const value = parseInt(cell.dataset.value);
  selectedSequence.push(value);
  cell.classList.add('selected');
  
  if (selectedSequence.length === targetSequence.length) {
    checkSequence();
  }
}

function checkSequence() {
  const mazeCells = document.querySelectorAll('.maze-cell');
  let correct = true;
  
  for (let i = 0; i < targetSequence.length; i++) {
    const cell = Array.from(mazeCells).find(c => parseInt(c.dataset.value) === selectedSequence[i]);
    if (selectedSequence[i] === targetSequence[i]) {
      cell.classList.add('correct');
    } else {
      cell.classList.add('wrong');
      correct = false;
    }
  }
  
  if (correct) {
    score += currentLevel * 10;
    document.getElementById('score').textContent = score;
    setTimeout(() => {
      currentLevel++;
      document.getElementById('level').textContent = currentLevel;
      startMemoryPhase();
    }, 1000);
  } else {
    setTimeout(() => {
      alert(`游戏结束！你的得分是: ${score}`);
      resetGame();
    }, 1000);
  }
}

function startMemoryPhase() {
  memoryPhase = true;
  document.getElementById('memoryPhase').style.display = 'block';
  document.getElementById('mazePhase').style.display = 'none';
  
  targetSequence = generateSequence(currentLevel + 2);
  selectedSequence = [];
  
  const numberDisplay = document.getElementById('numberDisplay');
  numberDisplay.textContent = targetSequence.join(' ');
  numberDisplay.classList.add('pulse');
  
  setTimeout(() => {
    numberDisplay.textContent = '';
    numberDisplay.classList.remove('pulse');
    startMazePhase();
  }, 2000 + currentLevel * 500);
}

function startMazePhase() {
  memoryPhase = false;
  document.getElementById('memoryPhase').style.display = 'none';
  document.getElementById('mazePhase').style.display = 'block';
  
  const mazeCells = document.querySelectorAll('.maze-cell');
  mazeCells.forEach(cell => {
    cell.classList.remove('selected', 'correct', 'wrong');
  });
}

function startGame() {
  if (gameStarted) return;
  gameStarted = true;
  currentLevel = 1;
  score = 0;
  document.getElementById('level').textContent = '1';
  document.getElementById('score').textContent = '0';
  
  const difficulty = document.getElementById('difficulty').value;
  timer = DIFFICULTY_TIMES[difficulty];
  document.getElementById('timer').textContent = timer;
  
  createMaze();
  startMemoryPhase();
  
  timerInterval = setInterval(() => {
    timer--;
    document.getElementById('timer').textContent = timer;
    
    if (timer <= 0) {
      clearInterval(timerInterval);
      alert(`时间到！你的得分是: ${score}`);
      resetGame();
    }
  }, 1000);
}

function resetGame() {
  gameStarted = false;
  clearInterval(timerInterval);
  document.getElementById('startGame').textContent = '重新开始';
}

document.getElementById('startGame').addEventListener('click', startGame);
document.getElementById('difficulty').addEventListener('change', resetGame);
</script> 