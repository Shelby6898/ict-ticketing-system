const DEPARTMENTS = {
  ict: {
    label: 'Directorate of ICT Services',
    icon: '🖥️',
    categories: {
      hardware: 'Hardware',
      software: 'Software',
      network: 'Network',
      account: 'Account/Access',
      other: 'Other'
    }
  },
  hr: {
    label: 'Registrar (HR & Administration)',
    icon: '🧑‍💼',
    categories: {
      leave: 'Leave & Absence',
      payroll: 'Payroll & Benefits',
      records: 'Records & Portal Access',
      recruitment: 'Recruitment & Onboarding',
      performance: 'Appraisal & Promotion',
      other: 'Other'
    }
  },
  finance: {
    label: 'Finance Department',
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
    label: 'Office of Academics, Student Affairs & Research',
    icon: '🎓',
    categories: {
      registration: 'Registration',
      transcripts: 'Transcripts',
      exams: 'Exams',
      grades: 'Grades',
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
