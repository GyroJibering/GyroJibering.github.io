---
layout: page
title: Friends
permalink: /friends/
---

<section class="profile-content">
  <div class="profile-content__panel">
    <div class="profile-section">
      <h2 class="profile-section__title">友链</h2>
      <div class="profile-section__content">
        <div class="friends-list">
          <div class="friend-item">
            <h3 class="friend-name">
              <a href="https://juryorca.github.io" target="_blank" rel="noopener noreferrer">Juryorca</a>
            </h3>
            <p class="friend-description">
              <strong>Pwn领域专家来啦！</strong><br>
              这位是深耕pwn领域的专家Juryorca大神，超级大神py，又称瑞幸首席幸运官lucky！
            </p>
            <p class="friend-link">
              <a href="https://juryorca.github.io" target="_blank" rel="noopener noreferrer">个人主页链接 →</a>
            </p>
          </div>

          <div class="friend-item">
            <h3 class="friend-name">
              <a href="https://lunaticquasimodo.top/link" target="_blank" rel="noopener noreferrer">LunaticQuasimodo</a>
            </h3>
            <p class="friend-description">
              <strong>Web大神</strong><br>
              LunaticQuasimodo，web大神；Pwn大神。
            </p>
            <p class="friend-link">
              <a href="https://lunaticquasimodo.top/link" target="_blank" rel="noopener noreferrer">个人主页 →</a>
            </p>
          </div>

          <div class="friend-item">
            <h3 class="friend-name">
              <a href="https://www.cameudis.com/" target="_blank" rel="noopener noreferrer">Y2</a>
            </h3>
            <p class="friend-description">
              <strong>Pwn大神 Y2 来啦！</strong><br>
              Sixstars的老队长，今年刚刚获得blackhat世界总冠军！无数fduer CTF的引路人，真正的大神。同时是知名偶像乐团的鼓手sama。
            </p>
            <p class="friend-link">
              <a href="https://www.cameudis.com/" target="_blank" rel="noopener noreferrer">个人主页链接 →</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<style>
.friends-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacer-2);
}

.friend-item {
  padding: var(--spacer);
  border-radius: var(--border-radius);
  background: rgba(255, 255, 255, .1);
  border: 1px solid rgba(255, 255, 255, .15);
  transition: all 0.3s ease;
}

.friend-item:hover {
  background: rgba(255, 255, 255, .15);
  border-color: rgba(255, 255, 255, .25);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, .2);
}

.friend-name {
  margin: 0 0 var(--spacer) 0;
  font-size: 1.3rem;
  color: var(--heading-color);
}

.friend-name a {
  color: var(--link-color);
  text-decoration: none;
  transition: color 0.2s ease;
}

.friend-name a:hover {
  color: var(--link-hover-color);
  text-decoration: underline;
}

.friend-description {
  margin: 0 0 var(--spacer) 0;
  line-height: 1.7;
  color: var(--gray-300);
}

.friend-description strong {
  color: var(--heading-color);
  font-size: 1.05em;
}

.friend-link {
  margin: var(--spacer) 0 0 0;
}

.friend-link a {
  display: inline-block;
  padding: 0.5rem 1rem;
  border-radius: var(--border-radius);
  background: rgba(34, 139, 230, .2);
  color: var(--link-color);
  text-decoration: none;
  transition: all 0.2s ease;
  border: 1px solid rgba(34, 139, 230, .3);
}

.friend-link a:hover {
  background: var(--link-color);
  color: #fff;
  border-color: var(--link-color);
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(34, 139, 230, .3);
}

@media (max-width: 40rem) {
  .friend-item {
    padding: calc(var(--spacer) * 0.75);
  }
  
  .friend-name {
    font-size: 1.1rem;
  }
}
</style>

