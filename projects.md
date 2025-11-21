---
layout: page
title: 项目经验
permalink: /projects/
---

<section class="blog-explorer">
  <header class="blog-explorer__hero">
    <p>展示我参与过的项目经历，快速预览项目亮点和技术栈，点开即可查看完整细节。</p>
    <label class="blog-search">
      <span class="blog-search__label">搜索项目</span>
      <input id="projects-search-input" type="search" placeholder="按标题、关键字过滤…" autocomplete="off">
    </label>
  </header>

  <div class="blog-explorer__panel">
    <div class="blog-explorer__list">
    {% assign project_posts = "" | split: "" %}
    {% for post in site.posts %}
      {% if post.categories contains "项目" %}
        {% assign project_posts = project_posts | push: post %}
      {% endif %}
    {% endfor %}
    {% if project_posts == empty %}
      <p class="blog-explorer__empty">暂时还没有项目，稍后再来看看吧。</p>
    {% else %}
      {% for post in project_posts %}
        {% assign content_id = 'project-' | append: forloop.index0 %}
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
              查看详情
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
  </div>
</section>

<script>
  window.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('projects-search-input');
    const cards = Array.from(document.querySelectorAll('[data-post]'));

    function toggleCard(button) {
      const target = document.getElementById(button.dataset.target);
      if (!target) { return; }
      const expanded = button.getAttribute('aria-expanded') === 'true';
      button.setAttribute('aria-expanded', String(!expanded));
      button.textContent = expanded ? '展开全文' : '收起全文';
      target.hidden = expanded;
    }

    cards.forEach((card) => {
      const button = card.querySelector('.blog-card__toggle');
      if (button) {
        button.addEventListener('click', () => toggleCard(button));
      }
    });

    if (searchInput) {
      const normalize = (text) => text.toLowerCase().replace(/\s+/g, ' ').trim();
      searchInput.addEventListener('input', (event) => {
        const keyword = normalize(event.target.value);
        cards.forEach((card) => {
          const text = normalize(card.textContent || '');
          const match = !keyword || text.includes(keyword);
          card.style.display = match ? '' : 'none';
        });
      });
    }
  });
</script>

