---
layout: page
title: 小恐龙跳跃
permalink: /dinosaur/
---

<section class="profile-content">
  <div class="profile-content__panel">
    <div class="profile-section">
      <h2 class="profile-section__title">游戏导航</h2>
      <div class="profile-section__content">
        <div class="game-navigation">
          <a href="/about/" class="game-nav-btn">记忆配对</a>
          <a href="/minesweeper/" class="game-nav-btn">扫雷游戏</a>
          <a href="/number-maze/" class="game-nav-btn">数字迷宫</a>
          <a href="/dinosaur/" class="game-nav-btn active">小恐龙</a>
        </div>
      </div>
    </div>

    <div class="profile-section">
      <h2 class="profile-section__title">小恐龙跳跃游戏</h2>
      <div class="profile-section__content">
        <div class="game-container">
          <div class="game-info">
            <div class="score">得分: <span id="score">0</span></div>
            <div class="high-score">最高分: <span id="highScore">0</span></div>
          </div>
          <div class="dinosaur-game-wrapper">
            <canvas id="gameCanvas" width="800" height="200"></canvas>
          </div>
          <div class="game-controls">
            <button id="startGame" class="game-button">开始游戏</button>
            <p class="game-instructions">按空格键或点击屏幕让恐龙跳跃，避开障碍物！</p>
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

.dinosaur-game-wrapper {
  display: flex;
  justify-content: center;
  margin: 2rem 0;
  background: #f8f9fa;
  border-radius: var(--border-radius);
  padding: 1rem;
  border: 1px solid rgba(0, 0, 0, .05);
}

#gameCanvas {
  max-width: 100%;
  height: auto;
  border-radius: var(--border-radius);
  background: #fff;
  box-shadow: 0 4px 12px rgba(0, 0, 0, .1);
}

.game-instructions {
  margin-top: 1rem;
  color: var(--gray-600);
  font-size: 0.9rem;
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
</style>

<script>
const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');

// Game state
let gameRunning = false;
let score = 0;
let highScore = parseInt(localStorage.getItem('dinosaurHighScore') || '0');
let gameSpeed = 5;
let gravity = 0.6;
let jumpPower = -15;

// Dinosaur
const dino = {
  x: 50,
  y: 150,
  width: 40,
  height: 40,
  velocityY: 0,
  grounded: true,
  color: '#228be6'
};

// Obstacles
const obstacles = [];
let obstacleTimer = 0;

// Ground
const groundY = 150;

// Initialize high score display
document.getElementById('highScore').textContent = highScore;

function drawDino() {
  ctx.fillStyle = dino.color;
  ctx.fillRect(dino.x, dino.y, dino.width, dino.height);
  
  // Draw simple eye
  ctx.fillStyle = '#fff';
  ctx.fillRect(dino.x + 25, dino.y + 10, 8, 8);
}

function drawObstacle(obstacle) {
  ctx.fillStyle = '#fa5252';
  ctx.fillRect(obstacle.x, obstacle.y, obstacle.width, obstacle.height);
}

function drawGround() {
  ctx.strokeStyle = '#dee2e6';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(0, groundY + dino.height);
  ctx.lineTo(canvas.width, groundY + dino.height);
  ctx.stroke();
}

function drawScore() {
  ctx.fillStyle = '#495057';
  ctx.font = '20px Arial';
  ctx.fillText(`得分: ${score}`, 20, 30);
}

function updateDino() {
  if (!dino.grounded) {
    dino.velocityY += gravity;
    dino.y += dino.velocityY;
    
    if (dino.y >= groundY) {
      dino.y = groundY;
      dino.velocityY = 0;
      dino.grounded = true;
    }
  }
}

function jump() {
  if (dino.grounded && gameRunning) {
    dino.velocityY = jumpPower;
    dino.grounded = false;
  }
}

function createObstacle() {
  obstacles.push({
    x: canvas.width,
    y: groundY,
    width: 20,
    height: 30,
    speed: gameSpeed
  });
}

function updateObstacles() {
  obstacleTimer++;
  const currentInterval = Math.max(60, 120 - Math.floor(score / 100));
  if (obstacleTimer >= currentInterval) {
    createObstacle();
    obstacleTimer = 0;
  }
  
  for (let i = obstacles.length - 1; i >= 0; i--) {
    obstacles[i].x -= obstacles[i].speed;
    
    if (obstacles[i].x + obstacles[i].width < 0) {
      obstacles.splice(i, 1);
      score++;
      document.getElementById('score').textContent = score;
      
      // Increase speed
      gameSpeed = 5 + Math.floor(score / 50);
    }
  }
}

function checkCollision() {
  for (let obstacle of obstacles) {
    if (dino.x < obstacle.x + obstacle.width &&
        dino.x + dino.width > obstacle.x &&
        dino.y < obstacle.y + obstacle.height &&
        dino.y + dino.height > obstacle.y) {
      return true;
    }
  }
  return false;
}

function gameLoop() {
  if (!gameRunning) return;
  
  // Clear canvas
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  
  // Update
  updateDino();
  updateObstacles();
  
  // Check collision
  if (checkCollision()) {
    gameOver();
    return;
  }
  
  // Draw
  drawGround();
  drawDino();
  obstacles.forEach(drawObstacle);
  drawScore();
  
  requestAnimationFrame(gameLoop);
}

function startGame() {
  if (gameRunning) return;
  
  gameRunning = true;
  score = 0;
  gameSpeed = 5;
  obstacles.length = 0;
  obstacleTimer = 0;
  dino.y = groundY;
  dino.velocityY = 0;
  dino.grounded = true;
  
  document.getElementById('score').textContent = '0';
  document.getElementById('startGame').textContent = '游戏中...';
  document.getElementById('startGame').disabled = true;
  
  gameLoop();
}

function gameOver() {
  gameRunning = false;
  document.getElementById('startGame').textContent = '重新开始';
  document.getElementById('startGame').disabled = false;
  
  if (score > highScore) {
    highScore = score;
    localStorage.setItem('dinosaurHighScore', highScore.toString());
    document.getElementById('highScore').textContent = highScore;
    alert(`游戏结束！新纪录：${score} 分！`);
  } else {
    alert(`游戏结束！得分：${score} 分`);
  }
}

// Event listeners
document.getElementById('startGame').addEventListener('click', startGame);

document.addEventListener('keydown', (e) => {
  if (e.code === 'Space') {
    e.preventDefault();
    jump();
  }
});

canvas.addEventListener('click', () => {
  if (gameRunning) {
    jump();
  } else {
    startGame();
  }
});

// Initial draw
ctx.clearRect(0, 0, canvas.width, canvas.height);
drawGround();
drawDino();
drawScore();
</script>

