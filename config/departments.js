const DEPARTMENTS = {
  ict: {
    label: 'ICT',
    icon: '🖥️',
    categories: {
      hardware: 'Hardware',
      software: 'Software',
      network: 'Network',
      account: 'Account/Access',
      other: 'Other'
    }
  },
  finance: {
    label: 'Finance',
    icon: '💰',
    categories: {
      fees: 'Fees',
      refunds: 'Refunds',
      payroll: 'Payroll',
      scholarship: 'Scholarship/Bursary',
      other: 'Other'
    }
  },
  academics: {
    label: 'Academics',
    icon: '🎓',
    categories: {
      registration: 'Registration',
      transcripts: 'Transcripts',
      exams: 'Exams',
      grades: 'Grades',
      other: 'Other'
    }
  },
  hostel: {
    label: 'Hostel/Accommodation',
    icon: '🏠',
    categories: {
      allocation: 'Room Allocation',
      maintenance: 'Maintenance',
      complaint: 'Complaint',
      transfer: 'Room Transfer',
      other: 'Other'
    }
  },
  library: {
    label: 'Library',
    icon: '📚',
    categories: {
      access: 'Access Issues',
      fines: 'Fines',
      request: 'Book Request',
      returns: 'Returns',
      other: 'Other'
    }
  }
};

const DEPARTMENT_KEYS = Object.keys(DEPARTMENTS);

function isValidDepartment(dept) {
  return DEPARTMENT_KEYS.includes(dept);
}

function isValidCategory(dept, category) {
  return !!(DEPARTMENTS[dept] && Object.prototype.hasOwnProperty.call(DEPARTMENTS[dept].categories, category));
}

module.exports = { DEPARTMENTS, DEPARTMENT_KEYS, isValidDepartment, isValidCategory };
