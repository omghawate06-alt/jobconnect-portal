
function searchJobs() {
  const input = document
    .getElementById("jobSearch")
    .value.toLowerCase();

  const jobs = document.querySelectorAll(".job-card");

  jobs.forEach(function (job) {
    const text = job.textContent.toLowerCase();

    if (text.includes(input)) {
      job.style.display = "block";
    } else {
      job.style.display = "none";
    }
  });
}
