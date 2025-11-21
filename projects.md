---
layout: page
title: 项目经验
permalink: /projects/
---

{% include profile-nav.html %}

<section class="profile-content">
  <div class="profile-content__panel">
    <div class="profile-section">
      <h2 class="profile-section__title">项目经历</h2>
      <div class="profile-section__content">
        <p style="margin-bottom: 1.5rem; color: var(--gray-600);">展示我参与过的项目经历，快速预览项目亮点和技术栈，点开即可查看完整细节。</p>
        
        <label class="profile-search">
          <input id="projects-search-input" type="search" placeholder="搜索项目…" autocomplete="off">
        </label>
      </div>
    </div>

    <div class="profile-projects-list">
      {% assign project_posts = "" | split: "" %}
      {% for post in site.posts %}
        {% if post.categories contains "项目" %}
          {% assign project_posts = project_posts | push: post %}
        {% endif %}
      {% endfor %}
      {% if project_posts == empty %}
        <div class="profile-project-item">
          <p style="text-align: center; color: var(--gray-600); padding: 2rem;">暂时还没有项目，稍后再来看看吧。</p>
        </div>
      {% else %}
        {% for post in project_posts %}
          {% assign content_id = 'project-' | append: forloop.index0 %}
          <div class="profile-project-item" data-post>
            <div class="profile-project-item__header">
              <div>
                <h3 class="profile-project-item__title">{{ post.title }}</h3>
                <p class="profile-project-item__date">{{ post.date | date: "%Y年%m月%d日" }}</p>
              </div>
              {% if post.tags %}
                <div class="profile-project-item__tags">
                  {% for tag in post.tags %}
                    <span class="profile-project-item__tag">{{ tag }}</span>
                  {% endfor %}
                </div>
              {% endif %}
            </div>
            
            <div class="profile-project-item__excerpt">
              {{ post.excerpt | strip_html | truncatewords: 30 }}
            </div>
            
            <div class="profile-project-item__actions">
              <a class="profile-project-item__link" href="{{ post.url | relative_url }}">
                查看详情
              </a>
              <button class="profile-project-item__toggle" type="button" aria-expanded="false" aria-controls="{{ content_id }}" data-target="{{ content_id }}">
                展开全文
              </button>
            </div>
            
            <div class="profile-project-item__full" id="{{ content_id }}" hidden>
              {{ post.content }}
            </div>
          </div>
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
      const button = card.querySelector('.profile-project-item__toggle');
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

