// ===== 论坛通用动效系统 =====

// 1. 滚动交错入场 (Intersection Observer)
const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      // 根据元素在列表中的位置计算延迟
      const index = Array.from(entry.target.parentElement.children).indexOf(entry.target);
      const delay = Math.max(0, index % 5) * 80; // 最多延迟 320ms，防止滚动太长等太久
      
      setTimeout(() => {
        entry.target.classList.add('visible');
      }, delay);
      
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

window.initReveal = function() {
  document.querySelectorAll('.reveal:not(.visible)').forEach(el => observer.observe(el));
};

// 2. 桌面端 3D 倾斜 (手机端触控不需要，且容易误触)
if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
  document.addEventListener('mousemove', (e) => {
    document.querySelectorAll('.card').forEach(card => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      
      if (Math.abs(x) < rect.width && Math.abs(y) < rect.height) {
        card.style.transform = `perspective(800px) rotateY(${x / rect.width * 4}deg) rotateX(${-y / rect.height * 4}deg) translateY(-4px)`;
      } else {
        card.style.transform = ''; 
      }
    });
  });
  // 鼠标离开窗口时重置所有卡片
  document.addEventListener('mouseleave', () => {
    document.querySelectorAll('.card').forEach(card => card.style.transform = '');
  });
}
