---
layout: page
title: Blog
permalink: /blog/
---

<style>
.page-title {
  display: none;
}

/* 分页控件样式，复用 profile-nav 风格 */
.pagination-controls {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 0.5rem;
  margin-top: 2rem;
  flex-wrap: wrap;
}

.pagination-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 2.5rem;
  height: 2.5rem;
  padding: 0 0.75rem;
  border-radius: 0.5rem;
  text-decoration: none;
  font-weight: 500;
  transition: all 0.2s ease;
  border: 1px solid rgba(0, 0, 0, 0.1);
  background: rgba(255, 255, 255, 0.8);
  color: var(--link-color);
  font-size: 0.95rem;
  cursor: pointer;
}

.pagination-btn:hover:not(:disabled):not(.active) {
  background: var(--link-color);
  color: #fff;
  border-color: var(--link-color);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(34, 139, 230, 0.3);
}

.pagination-btn.active {
  background: var(--link-color);
  color: #fff;
  border-color: var(--link-color);
  cursor: default;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  background: rgba(0, 0, 0, 0.05);
  color: var(--gray-600);
  box-shadow: none;
  transform: none;
}

@media (prefers-color-scheme: dark) {
  .pagination-btn {
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.15);
    color: var(--gray-300);
  }
  
  .pagination-btn:hover:not(:disabled):not(.active),
  .pagination-btn.active {
    background: var(--link-color);
    color: #fff;
    border-color: var(--link-color);
  }
}
</style>

<section class="blog-explorer">
  <header class="blog-explorer__hero">
    <p>把所有写过的内容整理在一起，快速预览主题和亮点，点开即可查看完整细节。</p>
    <label class="blog-search">
      <span class="blog-search__label">搜索文章</span>
      <input id="blog-search-input" type="search" placeholder="按标题、关键字过滤…" autocomplete="off">
    </label>
  </header>

  <div class="blog-explorer__panel">
    <div class="blog-explorer__list" id="blog-list">
    {% assign blog_posts = "" | split: "" %}
    {% for post in site.posts %}
      {% unless post.categories contains "项目" %}
        {% assign blog_posts = blog_posts | push: post %}
      {% endunless %}
    {% endfor %}
    {% if blog_posts == empty %}
      <p class="blog-explorer__empty">暂时还没有文章，稍后再来看看吧。</p>
    {% else %}
      {% for post in blog_posts %}
        {% assign content_id = 'post-' | append: forloop.index0 %}
        <article class="blog-card" data-post>
          <header class="blog-card__header">
            <div>
              <p class="blog-card__date">{{ post.date | date: "%Y-%m-%d" }}</p>
              <h2 class="blog-card__title">{{ post.title }}</h2>
            </div>
            <div class="blog-card__meta">
              {% if post.categories.size > 0 %}
                <span class="blog-card__chip">{{ post.categories | join: ' / ' }}</span>
              {% endif %}
              {% if post.tags %}
                <span class="blog-card__chip blog-card__chip--ghost">{{ post.tags | join: ' · ' }}</span>
              {% endif %}
            </div>
          </header>

          <p class="blog-card__excerpt">
            {{ post.excerpt | strip_html | truncatewords: 42 }}
          </p>

          <div class="blog-card__actions">
            <a class="blog-card__link" href="{{ post.url | relative_url }}">
              阅读原文
            </a>
            <button class="blog-card__toggle" type="button" aria-expanded="false" aria-controls="{{ content_id }}" data-target="{{ content_id }}">
              展开全文
            </button>
          </div>

          <div class="blog-card__full" id="{{ content_id }}" hidden>
            {{ post.content }}
          </div>
        </article>
        {% endfor %}
    {% endif %}
    </div>
    
    <!-- 分页控件容器 -->
    <div id="pagination-controls" class="pagination-controls"></div>
  </div>
</section>

<script>
  window.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('blog-search-input');
    const allCards = Array.from(document.querySelectorAll('[data-post]'));
    const paginationContainer = document.getElementById('pagination-controls');
    const blogList = document.getElementById('blog-list');
    
    // 分页配置
    const itemsPerPage = 10;
    let currentPage = 1;
    let visibleCards = [...allCards]; // 当前需要显示的卡片（可能被搜索过滤）

    // 展开/收起功能
    function toggleCard(button) {
      const target = document.getElementById(button.dataset.target);
      if (!target) { return; }
      const expanded = button.getAttribute('aria-expanded') === 'true';
      button.setAttribute('aria-expanded', String(!expanded));
      button.textContent = expanded ? '展开全文' : '收起全文';
      target.hidden = expanded;
    }

    // 绑定点击事件
    allCards.forEach((card) => {
      const button = card.querySelector('.blog-card__toggle');
      if (button) {
        button.addEventListener('click', () => toggleCard(button));
      }
    });

    // 渲染分页控件
    function renderPagination() {
      paginationContainer.innerHTML = '';
      const totalPages = Math.ceil(visibleCards.length / itemsPerPage);
      
      // 如果只有1页或没有内容，不显示分页
      if (totalPages <= 1) {
        paginationContainer.style.display = 'none';
        return;
      }
      paginationContainer.style.display = 'flex';

      // 上一页按钮
      const prevBtn = document.createElement('button');
      prevBtn.className = 'pagination-btn';
      prevBtn.innerHTML = '←';
      prevBtn.disabled = currentPage === 1;
      prevBtn.addEventListener('click', () => changePage(currentPage - 1));
      paginationContainer.appendChild(prevBtn);

      // 页码按钮
      // 简单的页码逻辑：显示所有页码（如果页数很多，可以后续优化为 1 2 ... 9 10）
      // 这里为了样式美观，最多显示5个页码
      let startPage = Math.max(1, currentPage - 2);
      let endPage = Math.min(totalPages, startPage + 4);
      
      if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
      }

      if (startPage > 1) {
         const firstBtn = document.createElement('button');
         firstBtn.className = 'pagination-btn';
         firstBtn.textContent = '1';
         firstBtn.addEventListener('click', () => changePage(1));
         paginationContainer.appendChild(firstBtn);
         
         if (startPage > 2) {
           const dots = document.createElement('span');
           dots.textContent = '...';
           dots.style.opacity = '0.5';
           paginationContainer.appendChild(dots);
         }
      }

      for (let i = startPage; i <= endPage; i++) {
        const btn = document.createElement('button');
        btn.className = `pagination-btn ${i === currentPage ? 'active' : ''}`;
        btn.textContent = i;
        if (i !== currentPage) {
          btn.addEventListener('click', () => changePage(i));
        }
        paginationContainer.appendChild(btn);
      }

      if (endPage < totalPages) {
         if (endPage < totalPages - 1) {
           const dots = document.createElement('span');
           dots.textContent = '...';
           dots.style.opacity = '0.5';
           paginationContainer.appendChild(dots);
         }
         
         const lastBtn = document.createElement('button');
         lastBtn.className = 'pagination-btn';
         lastBtn.textContent = totalPages;
         lastBtn.addEventListener('click', () => changePage(totalPages));
         paginationContainer.appendChild(lastBtn);
      }

      // 下一页按钮
      const nextBtn = document.createElement('button');
      nextBtn.className = 'pagination-btn';
      nextBtn.innerHTML = '→';
      nextBtn.disabled = currentPage === totalPages;
      nextBtn.addEventListener('click', () => changePage(currentPage + 1));
      paginationContainer.appendChild(nextBtn);
    }

    // 切换页面
    function changePage(page) {
      const totalPages = Math.ceil(visibleCards.length / itemsPerPage);
      if (page < 1 || page > totalPages) return;
      
      currentPage = page;
      updateDisplay();
      
      // 滚动到列表顶部
      const listTop = document.querySelector('.blog-explorer__hero').getBoundingClientRect().bottom + window.scrollY;
      window.scrollTo({ top: listTop - 20, behavior: 'smooth' });
    }

    // 更新显示状态
    function updateDisplay() {
      // 首先隐藏所有卡片
      allCards.forEach(card => card.style.display = 'none');
      
      const start = (currentPage - 1) * itemsPerPage;
      const end = start + itemsPerPage;
      
      // 显示当前页的卡片
      visibleCards.slice(start, end).forEach(card => {
        card.style.display = '';
      });

      renderPagination();
    }

    // 搜索功能
    if (searchInput) {
      const normalize = (text) => text.toLowerCase().replace(/\s+/g, ' ').trim();
      
      searchInput.addEventListener('input', (event) => {
        const keyword = normalize(event.target.value);
        
        if (!keyword) {
          // 搜索清空，恢复全部分页显示
          visibleCards = [...allCards];
          // 保持当前页或重置为1？重置为1通常比较合理
          currentPage = 1; 
          updateDisplay();
          return;
        }

        // 搜索模式：过滤卡片
        visibleCards = allCards.filter(card => {
          const text = normalize(card.textContent || '');
          return text.includes(keyword);
        });

        // 搜索模式下，分页：如果结果超过10个，依然分页？
        // 用户需求是“搜索过滤”，通常搜索结果不强制分页，但如果结果很多，分页也无妨。
        // 这里为了统一体验，搜索结果也进行分页。
        currentPage = 1;
        updateDisplay();
      });
    }

    // 初始化
    updateDisplay();
  });
</script>