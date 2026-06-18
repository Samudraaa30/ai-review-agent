import sys
from pathlib import Path

sys.path.append(
    str(
        Path(__file__).resolve().parent.parent
    )
)

import streamlit as st

from backend.review_store import (
    load_reviews,
    save_reviews
)

# Load existing reviews for display/editing
reviews = load_reviews() or []

st.set_page_config(
    page_title="Manager Portal",
    layout="wide"
)

st.title(
    "📊 Manager Portal"
)
filter_status = st.selectbox(
    "Filter",
    [
        "All",
        "Pending",
        "Approved",
        "Rejected"
    ]
)
pending = len(
    [
        r
        for r in reviews
        if r.get(
            "status",
            "Pending"
        ) == "Pending"
    ]
)

approved = len(
    [
        r
        for r in reviews
        if r.get(
            "status",
            "Pending"
        ) == "Approved"
    ]
)

rejected = len(
    [
        r
        for r in reviews
        if r.get(
            "status",
            "Pending"
        ) == "Rejected"
    ]
)
c1, c2, c3 = st.columns(3)

c1.metric(
    "Pending Reviews",
    pending
)

c2.metric(
    "Approved Reviews",
    approved
)

c3.metric(
    "Rejected Reviews",
    rejected
)
report_file = "report.pdf"
for i, review in enumerate(reviews):
    if (
        filter_status != "All"
        and review.get(
            "status",
            "Pending"
        ) != filter_status
    ):
        continue

    st.subheader(
        review.get(
            "repo",
            "Unknown Repo"
        )
    )

    st.write(
        f"Review Type: {review.get('review_type','N/A')}"
    )

    st.write(
        f"Risk Score: {review.get('risk_score','N/A')}"
    )
    pdf_path = review.get(
    "pdf_path"
    )

    if pdf_path:

     try:

        with open(
            pdf_path,
            "rb"
        ) as pdf_file:

            st.download_button(
                "📄 Download Report",
                pdf_file,
                file_name="Review_Report.pdf",
                mime="application/pdf",
                key=f"pdf_{i}"
            )

     except:

        st.warning(
            "Report not found"
        )
    st.write(
       f"Submitted: {review.get('timestamp','N/A')}"
    )

    st.write(
      f"Submitted By: {review.get('submitted_by','N/A')}"
    )
    try:

      with open(
        report_file,
        "rb"
      ) as pdf_file:

        st.download_button(
            "📄 Download Latest Report",
            pdf_file,
            file_name="Review_Report.pdf",
            mime="application/pdf"
        )

    except:

     st.warning(
        "No report available."
     )
    st.write(
        f"Current Status: {review.get('status','Pending')}"
    )

    status = st.selectbox(
        "Status",
        [
            "Pending",
            "Approved",
            "Rejected"
        ],
        key=f"status_{i}"
    )

    comment = st.text_area(
    "Manager Comment",
    value=review.get(
        "manager_comment",
        ""
    ),
    key=f"comment_{i}"
    )   
    review["status"] = status

    review["manager_comment"] = comment

    st.divider()
if st.button(
    "💾 Save Reviews"
):

    save_reviews(
        reviews
    )

    st.success(
        "Reviews Saved"
    )