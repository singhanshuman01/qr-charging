function stopCharging(userId) {
    window.location.href = `/stop_charging/${userId}`;
  }
  
  window.onload = function () {
    const countdownTimer = document.getElementById("countdown-timer");
    let timeLeft = 300; // 5 minutes in seconds
  
    const timer = setInterval(() => {
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      countdownTimer.textContent = `Time Remaining: ${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
      
      if (timeLeft <= 0) {
        clearInterval(timer);
        alert("Charging stopped automatically.");
        window.location.href = '/login';
      }
  
      timeLeft--;
    }, 1000);
  };
  