/**
 * Devise Onboarding Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('setupForm');
  
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email')?.value.trim();
    const name = document.getElementById('name')?.value.trim();
    const department = document.getElementById('department')?.value;
    
    if (!email || !name || !department) return;
    
    const btn = form.querySelector('.btn');
    btn.disabled = true;
    btn.textContent = 'Setting up...';
    
    try {
      await sendMessage({
        action: 'setIdentity',
        identity: {
          id: email,
          email,
          name,
          department,
          source: 'onboarding'
        }
      });
      
      btn.textContent = '✓ Setup Complete';
      btn.style.background = 'linear-gradient(135deg, #10B981 0%, #059669 100%)';
      
      setTimeout(() => window.close(), 1000);
      
    } catch (error) {
      console.error('Setup failed:', error);
      btn.disabled = false;
      btn.textContent = 'Complete Setup';
    }
  });
  
  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
  }
});
