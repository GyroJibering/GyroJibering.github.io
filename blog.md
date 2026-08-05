---
layout: page
title: Blog
permalink: /blog/
---

<style>
.page-title {
  display: none;
}
</style>

<section class="blog-explorer">
  <header class="blog-explorer__hero">
    <div class="blog-hero-copy">
      <p class="eyebrow">GYROJ · SECURITY NOTES</p>
      <h1>把复杂的问题，<br>拆成可验证的答案。</h1>
      <p class="blog-hero-summary">记录 Web 安全、逆向工程、CTF 与真实世界中的技术探索。少一些结论，多一些推导过程。</p>
    </div>
    <div class="blog-hero-aside">
      <dl class="blog-hero-facts" aria-label="博客信息">
        <div>
          <dt>{{ site.posts | size }}</dt>
          <dd>篇技术记录</dd>
        </div>
        <div>
          <dt>Web / RE</dt>
          <dd>持续关注方向</dd>
        </div>
      </dl>
      <a href="https://discord.gg/CWg9Tu6mDt" target="_blank" rel="noopener noreferrer" class="discord-link">
        加入 Discord <span aria-hidden="true">↗</span>
      </a>
    </div>
  </header>

  <div class="blog-toolbar">
    <div>
      <p class="eyebrow">LATEST WRITING</p>
      <h2>文章与研究笔记</h2>
    </div>
    <label class="blog-search">
      <span class="blog-search__label">搜索文章</span>
      <input id="blog-search-input" type="search" placeholder="标题、方向或关键字" autocomplete="off">
    </label>
  </div>

  <div class="blog-explorer__panel">
    <div class="blog-explorer__list">
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
              <p class="blog-card__date"><span>{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>{{ post.date | date: "%Y.%m.%d" }}</p>
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
  </div>
</section>

<script>
  window.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('blog-search-input');
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
