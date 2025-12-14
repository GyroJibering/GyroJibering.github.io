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
          <div class="friend-card">
            <div class="friend-card__avatar">
              <img src="/img/friends/Juryorca.png" alt="Juryorca" class="friend-avatar">
            </div>
            <div class="friend-card__content">
              <h3 class="friend-card__name">
                <a href="https://juryorca.github.io" target="_blank" rel="noopener noreferrer">Juryorca</a>
              </h3>
              <p class="friend-card__title">Pwn领域专家来啦！</p>
              <p class="friend-card__description">
                这位是深耕pwn领域的专家Juryorca大神，超级大神py，又称瑞幸首席幸运官lucky！
              </p>
              <a href="https://juryorca.github.io" target="_blank" rel="noopener noreferrer" class="friend-card__link">
                访问主页 →
              </a>
            </div>
          </div>

          <div class="friend-card">
            <div class="friend-card__avatar">
              <img src="/img/friends/lunaticQusimodo.jpg" alt="LunaticQuasimodo" class="friend-avatar">
            </div>
            <div class="friend-card__content">
              <h3 class="friend-card__name">
                <a href="https://lunaticquasimodo.top/link" target="_blank" rel="noopener noreferrer">LunaticQuasimodo</a>
              </h3>
              <p class="friend-card__title">Web大神</p>
              <p class="friend-card__description">
                LunaticQuasimodo 一位高调的白客，个人主页十分精美，征婚中，有意向的自己联系。
              </p>
              <a href="https://lunaticquasimodo.top" target="_blank" rel="noopener noreferrer" class="friend-card__link">
                访问主页 →
              </a>
            </div>
          </div>

          <div class="friend-card">
            <div class="friend-card__avatar">
              <img src="/img/friends/yy.png" alt="Y2" class="friend-avatar">
            </div>
            <div class="friend-card__content">
              <h3 class="friend-card__name">
                <a href="https://www.cameudis.com/" target="_blank" rel="noopener noreferrer">Y2</a>
              </h3>
              <p class="friend-card__title">Pwn大神 Y2 来啦！</p>
              <p class="friend-card__description">
                Sixstars的老队长，无数fduer CTF的引路人，真正的大神。同时是知名偶像乐团的鼓手sama。
              </p>
              <a href="https://www.cameudis.com/" target="_blank" rel="noopener noreferrer" class="friend-card__link">
                访问主页 →
              </a>
            </div>
          </div>

          <div class="friend-card">
            <div class="friend-card__avatar">
              <img src="/img/friends/Hencecho.jpg" alt="Hencecho" class="friend-avatar">
            </div>
            <div class="friend-card__content">
              <h3 class="friend-card__name">
                <a href="#" target="_blank" rel="noopener noreferrer">Hencecho</a>
              </h3>
              <p class="friend-card__title">算法大神</p>
              <p class="friend-card__description">
                计算机领域大神，算法大神，从二年级就开始学算法的顶级ACM选手。
              </p>
              <a href="https://www.cnblogs.com/Hencecho" target="_blank" rel="noopener noreferrer" class="friend-card__link">
                访问主页 →
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<style>
.friends-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: var(--spacer-2);
  margin-top: var(--spacer);
}

.friend-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacer-2);
  border-radius: calc(var(--border-radius) * 2);
  background: rgba(255, 255, 255, .08);
  border: 1px solid rgba(255, 255, 255, .12);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  text-align: center;
  position: relative;
  overflow: hidden;
}

.friend-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: linear-gradient(90deg, rgba(34, 139, 230, .8), rgba(18, 184, 134, .8));
  opacity: 0;
  transition: opacity 0.3s ease;
}

.friend-card:hover {
  background: rgba(255, 255, 255, .12);
  border-color: rgba(255, 255, 255, .2);
  box-shadow: 0 8px 24px rgba(0, 0, 0, .3);
  transform: translateY(-4px);
}

.friend-card:hover::before {
  opacity: 1;
}

.friend-card__avatar {
  width: 120px;
  height: 120px;
  margin-bottom: var(--spacer);
  position: relative;
  flex-shrink: 0;
}

.friend-avatar {
  width: 100%;
  height: 100%;
  object-fit: cover;
  border-radius: 50%;
  border: 3px solid rgba(255, 255, 255, .2);
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(0, 0, 0, .2);
}

.friend-card:hover .friend-avatar {
  border-color: rgba(34, 139, 230, .6);
  box-shadow: 0 6px 20px rgba(34, 139, 230, .4);
  transform: scale(1.05);
}

.friend-card__content {
  flex: 1;
  display: flex;
  flex-direction: column;
  width: 100%;
}

.friend-card__name {
  margin: 0 0 0.5rem 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--heading-color);
}

.friend-card__name a {
  color: var(--link-color);
  text-decoration: none;
  transition: color 0.2s ease;
}

.friend-card__name a:hover {
  color: var(--link-hover-color);
}

.friend-card__title {
  margin: 0 0 var(--spacer) 0;
  font-size: 1rem;
  font-weight: 500;
  color: rgba(34, 139, 230, .9);
  opacity: 0.9;
}

.friend-card__description {
  margin: 0 0 var(--spacer) 0;
  line-height: 1.7;
  color: var(--gray-300);
  font-size: 0.95rem;
  flex: 1;
}

.friend-card__link {
  display: inline-block;
  margin-top: auto;
  padding: 0.75rem 1.5rem;
  border-radius: 999px;
  background: rgba(34, 139, 230, .2);
  color: var(--link-color);
  text-decoration: none;
  font-weight: 500;
  transition: all 0.3s ease;
  border: 1px solid rgba(34, 139, 230, .3);
  align-self: center;
}

.friend-card__link:hover {
  background: var(--link-color);
  color: #fff;
  border-color: var(--link-color);
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(34, 139, 230, .4);
}

@media (max-width: 40rem) {
  .friends-list {
    grid-template-columns: 1fr;
    gap: var(--spacer);
  }
  
  .friend-card {
    padding: var(--spacer);
  }
  
  .friend-card__avatar {
    width: 100px;
    height: 100px;
  }
  
  .friend-card__name {
    font-size: 1.3rem;
  }
  
  .friend-card__description {
    font-size: 0.9rem;
  }
}

@media (min-width: 768px) {
  .friends-list {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1200px) {
  .friends-list {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>

