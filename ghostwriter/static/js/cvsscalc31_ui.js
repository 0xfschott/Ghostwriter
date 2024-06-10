function AttackVector(){
    if (document.getElementById('AV_N').checked) {return "N";}
    else if (document.getElementById('AV_A').checked) {return "A";}
    else if (document.getElementById('AV_L').checked) {return "L";}
    else if (document.getElementById('AV_P').checked) {return "P";}
    else {return null;}
}

function AttackComplexity(){
    if (document.getElementById('AC_L').checked) {return "L";}
    else if (document.getElementById('AC_H').checked) {return "H";}
    else {return null;}
}

function PrivilegesRequired(){
    if (document.getElementById('PR_N').checked) {return "N";}
    else if (document.getElementById('PR_L').checked) {return "L";}
    else if (document.getElementById('PR_H').checked) {return "H";}
    else {return null;}
}

function UserInteraction(){
    if (document.getElementById('UI_N').checked) {return "N";}
    else if (document.getElementById('UI_R').checked) {return "R";}
    else {return null;}
}

function Scope(){
    if (document.getElementById('S_U').checked) {return "U";}
    else if (document.getElementById('S_C').checked) {return "C";}
    else {return null;}
}

function Confidentiality(){
    if (document.getElementById('C_N').checked) {return "N";}
    else if (document.getElementById('C_L').checked) {return "L";}
    else if (document.getElementById('C_H').checked) {return "H";}
    else {return null;}
}

function Integrity (){
    if (document.getElementById('I_N').checked) {return "N";}
    else if (document.getElementById('I_L').checked) {return "L";}
    else if (document.getElementById('I_H').checked) {return "H";}
    else {return null;}
}

function Availability(){
    if (document.getElementById('A_N').checked) {return "N";}
    else if (document.getElementById('A_L').checked) {return "L";}
    else if (document.getElementById('A_H').checked) {return "H";}
    else {return null;}
}

function ExploitCodeMaturity(){
    if (document.getElementById('E_X').checked) {return "X";}
    else if (document.getElementById('E_U').checked) {return "U";}
    else if (document.getElementById('E_P').checked) {return "P";}
    else if (document.getElementById('E_F').checked) {return "F";}
    else if (document.getElementById('E_H').checked) {return "H";}
    else {return null;}
}

function RemediationLevel(){
    if (document.getElementById('RL_X').checked) {return "X";}
    else if (document.getElementById('RL_O').checked) {return "O";}
    else if (document.getElementById('RL_T').checked) {return "T";}
    else if (document.getElementById('RL_W').checked) {return "W";}
    else if (document.getElementById('RL_U').checked) {return "U";}
    else {return null;}
}

function ReportConfidence(){
    if (document.getElementById('RC_X').checked) {return "X";}
    else if (document.getElementById('RC_U').checked) {return "U";}
    else if (document.getElementById('RC_R').checked) {return "R";}
    else if (document.getElementById('RC_C').checked) {return "C";}
    else {return null;}
}

function ConfidentialityRequirement(){
    if (document.getElementById('CR_X').checked) {return "X";}
    else if (document.getElementById('CR_L').checked) {return "L";}
    else if (document.getElementById('CR_M').checked) {return "M";}
    else if (document.getElementById('CR_H').checked) {return "H";}
    else {return null;}
}

function IntegrityRequirement(){
    if (document.getElementById('IR_X').checked) {return "X";}
    else if (document.getElementById('IR_L').checked) {return "L";}
    else if (document.getElementById('IR_M').checked) {return "M";}
    else if (document.getElementById('IR_H').checked) {return "H";}
    else {return null;}
}

function AvailabilityRequirement(){
    if (document.getElementById('AR_X').checked) {return "X";}
    else if (document.getElementById('AR_L').checked) {return "L";}
    else if (document.getElementById('AR_M').checked) {return "M";}
    else if (document.getElementById('AR_H').checked) {return "H";}
    else {return null;}
}

function ModifiedAttackVector(){
    if (document.getElementById('MAV_N').checked) {return "N";}
    else if (document.getElementById('MAV_A').checked) {return "A";}
    else if (document.getElementById('MAV_L').checked) {return "L";}
    else if (document.getElementById('MAV_P').checked) {return "P";}
    else {return null;}
}

function ModifiedAttackComplexity(){
    if (document.getElementById('MAC_L').checked) {return "L";}
    else if (document.getElementById('MAC_H').checked) {return "H";}
    else {return null;}
}

function ModifiedPrivilegesRequired(){
    if (document.getElementById('MPR_N').checked) {return "N";}
    else if (document.getElementById('MPR_L').checked) {return "L";}
    else if (document.getElementById('MPR_H').checked) {return "H";}
    else {return null;}
}

function ModifiedUserInteraction(){
    if (document.getElementById('MUI_N').checked) {return "N";}
    else if (document.getElementById('MUI_R').checked) {return "R";}
    else {return null;}
}

function ModifiedScope(){
    if (document.getElementById('MS_U').checked) {return "U";}
    else if (document.getElementById('MS_C').checked) {return "C";}
    else {return null;}
}

function ModifiedConfidentiality(){
    if (document.getElementById('MC_N').checked) {return "N";}
    else if (document.getElementById('MC_L').checked) {return "L";}
    else if (document.getElementById('MC_H').checked) {return "H";}
    else {return null;}
}

function ModifiedIntegrity(){
    if (document.getElementById('MI_N').checked) {return "N";}
    else if (document.getElementById('MI_L').checked) {return "L";}
    else if (document.getElementById('MI_H').checked) {return "H";}
    else {return null;}
}

function ModifiedAvailability(){
    if (document.getElementById('MA_N').checked) {return "N";}
    else if (document.getElementById('MA_L').checked) {return "L";}
    else if (document.getElementById('MA_H').checked) {return "H";}
    else {return null;}
}

function ParseVector(vectorString){
    var metricValues = {
      AV:  undefined, AC:  undefined, PR:  undefined, UI:  undefined, S:  undefined,
      C:   undefined, I:   undefined, A:   undefined,
      E:   undefined, RL:  undefined, RC:  undefined,
      CR:  undefined, IR:  undefined, AR:  undefined,
      MAV: undefined, MAC: undefined, MPR: undefined, MUI: undefined, MS: undefined,
      MC: undefined, MI: undefined, MA: undefined
    };
    var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");
    for (var i in metricNameValue) {
      if (metricNameValue.hasOwnProperty(i)) {
        var singleMetric = metricNameValue[i].split(":");
        if (typeof metricValues[singleMetric[0]] === "undefined") {
          metricValues[singleMetric[0]] = singleMetric[1];
        }
      }
    }
    switch (metricValues.AV) {
      case 'N':
        document.getElementById('AV_N').checked = true;
        break;
      case 'A':
        document.getElementById('AV_A').checked = true;
        break;
      case 'L':
        document.getElementById('AV_L').checked = true;
        break;
      case 'P':
        document.getElementById('AV_P').checked = true;
        break;
    }
    switch (metricValues.AC) {
      case 'L':
        document.getElementById('AC_L').checked = true;
        break;
      case 'H':
        document.getElementById('AC_H').checked = true;
        break;
    }
    switch (metricValues.PR) {
      case 'N':
        document.getElementById('PR_N').checked = true;
        break;
      case 'L':
        document.getElementById('PR_L').checked = true;
        break;
      case 'H':
        document.getElementById('PR_H').checked = true;
        break;
    }
    switch (metricValues.UI) {
      case 'R':
        document.getElementById('UI_R').checked = true;
        break;
      case 'N':
        document.getElementById('UI_N').checked = true;
        break;
    }
    switch (metricValues.S) {
      case 'U':
        document.getElementById('S_U').checked = true;
        break;
      case 'C':
        document.getElementById('S_C').checked = true;
        break;
    }
    switch (metricValues.C) {
      case 'N':
        document.getElementById('C_N').checked = true;
        break;
      case 'L':
        document.getElementById('C_L').checked = true;
        break;
      case 'H':
        document.getElementById('C_H').checked = true;
        break;
    }
    switch (metricValues.I) {
      case 'N':
        document.getElementById('I_N').checked = true;
        break;
      case 'L':
        document.getElementById('I_L').checked = true;
        break;
      case 'H':
        document.getElementById('I_H').checked = true;
        break;
    }
    switch (metricValues.A) {
      case 'N':
        document.getElementById('A_N').checked = true;
        break;
      case 'L':
        document.getElementById('A_L').checked = true;
        break;
      case 'H':
        document.getElementById('A_H').checked = true;
        break;
    }
    switch (metricValues.E) {
      case 'X':
        document.getElementById('E_X').checked = true;
        break;
      case 'U':
        document.getElementById('E_U').checked = true;
        break;
      case 'P':
        document.getElementById('E_P').checked = true;
        break;
      case 'F':
        document.getElementById('E_F').checked = true;
        break;
      case 'H':
        document.getElementById('E_H').checked = true;
        break;
    }
    switch (metricValues.RL) {
      case 'X':
        document.getElementById('RL_X').checked = true;
        break;
      case 'O':
        document.getElementById('RL_O').checked = true;
        break;
      case 'T':
        document.getElementById('RL_T').checked = true;
        break;
      case 'W':
        document.getElementById('RL_W').checked = true;
        break;
      case 'U':
        document.getElementById('RL_U').checked = true;
        break;
    }
    switch (metricValues.RC) {
      case 'X':
        document.getElementById('RC_X').checked = true;
        break;
      case 'U':
        document.getElementById('RC_U').checked = true;
        break;
      case 'R':
        document.getElementById('RC_R').checked = true;
        break;
      case 'C':
        document.getElementById('RC_C').checked = true;
        break;
    }
    switch (metricValues.CR) {
      case 'X':
        document.getElementById('CR_X').checked = true;
        break;
      case 'L':
        document.getElementById('CR_L').checked = true;
        break;
      case 'M':
        document.getElementById('CR_M').checked = true;
        break;
      case 'H':
        document.getElementById('CR_H').checked = true;
        break;
    }
    switch (metricValues.IR) {
      case 'X':
        document.getElementById('IR_X').checked = true;
        break;
      case 'L':
        document.getElementById('IR_L').checked = true;
        break;
      case 'M':
        document.getElementById('IR_M').checked = true;
        break;
      case 'H':
        document.getElementById('IR_H').checked = true;
        break;
    }
    switch (metricValues.AR) {
      case 'X':
        document.getElementById('AR_X').checked = true;
        break;
      case 'L':
        document.getElementById('AR_L').checked = true;
        break;
      case 'M':
        document.getElementById('AR_M').checked = true;
        break;
      case 'H':
        document.getElementById('AR_H').checked = true;
        break;
    }
    switch (metricValues.MAV) {
        case 'N':
          document.getElementById('MAV_N').checked = true;
          break;
        case 'A':
          document.getElementById('MAV_A').checked = true;
          break;
        case 'L':
          document.getElementById('MAV_L').checked = true;
          break;
        case 'P':
        document.getElementById('MAV_P').checked = true;
        break;
    }
    switch (metricValues.MAC) {
        case 'L':
          document.getElementById('MAC_L').checked = true;
          break;
        case 'H':
          document.getElementById('MAC_H').checked = true;
          break;
    }
    switch (metricValues.MPR) {
        case 'N':
          document.getElementById('MPR_N').checked = true;
          break;
        case 'L':
          document.getElementById('MPR_L').checked = true;
          break;
        case 'H':
          document.getElementById('MPR_H').checked = true;
          break;
    }
    switch (metricValues.MUI) {
        case 'N':
          document.getElementById('MUI_N').checked = true;
          break;
        case 'R':
          document.getElementById('MUI_R').checked = true;
          break;
    }
    switch (metricValues.MS) {
        case 'U':
          document.getElementById('MS_U').checked = true;
          break;
        case 'C':
          document.getElementById('MS_C').checked = true;
          break;
    }
    switch (metricValues.MC) {
        case 'N':
          document.getElementById('MC_N').checked = true;
          break;
        case 'L':
          document.getElementById('MC_L').checked = true;
          break;
        case 'H':
          document.getElementById('MC_H').checked = true;
          break;
    }
    switch (metricValues.MI) {
        case 'N':
          document.getElementById('MI_N').checked = true;
          break;
        case 'L':
          document.getElementById('MI_L').checked = true;
          break;
        case 'H':
          document.getElementById('MI_H').checked = true;
          break;
    }
    switch (metricValues.MA) {
        case 'N':
          document.getElementById('MA_N').checked = true;
          break;
        case 'L':
          document.getElementById('MA_L').checked = true;
          break;
        case 'H':
          document.getElementById('MA_H').checked = true;
          break;
    }
}

function CVSSAutoCalc(){
    var count = 0;
    var baseFields = ["AV","AC","PR","UI","S","C","I","A"];
    for (var i = 0; i < baseFields.length; i++){
      var elements = document.getElementsByName(baseFields[i]);
      for (var j = 0; j < elements.length; j++){
        if (elements[j].checked === true){ count++; }
      }
    }
    if (count == 8){ CVSSScore(); }
}

function CVSSScore(){
    var metrics = {
        AV: AttackVector(),
        AC: AttackComplexity(),
        PR: PrivilegesRequired(),
        UI: UserInteraction(),
        S: Scope(),
        C: Confidentiality(),
        I: Integrity(),
        A: Availability(),
        E: ExploitCodeMaturity(),
        RL: RemediationLevel(),
        RC: ReportConfidence(),
        CR: ConfidentialityRequirement(),
        IR: IntegrityRequirement(),
        AR: AvailabilityRequirement(),
        MAV: ModifiedAttackVector(),
        MAC: ModifiedAttackComplexity(),
        MPR: ModifiedPrivilegesRequired(),
        MUI: ModifiedUserInteraction(),
        MS: ModifiedScope(),
        MC: ModifiedConfidentiality(),
        MI: ModifiedIntegrity(),
        MA: ModifiedAvailability()
    };

    var output = CVSS.calculateCVSSFromMetrics(
        metrics.AV, metrics.AC, metrics.PR, metrics.UI, metrics.S,
        metrics.C, metrics.I, metrics.A, metrics.E, metrics.RL, 
        metrics.RC, metrics.CR, metrics.IR, metrics.AR,
        metrics.MAV, metrics.MAC, metrics.MPR, metrics.MUI,
        metrics.MS, metrics.MC, metrics.MI, metrics.MA
    );

    if (output.success === true) {
        document.getElementById('id_cvss_score').value = output.environmentalMetricScore;
        document.getElementById('id_cvss_vector').value = output.vectorString;

        if (output.baseMetricScore >= 9.0){
            document.getElementById('id_severity').value = 5;
        } else if (output.baseMetricScore >= 7.0){
            document.getElementById('id_severity').value = 4;
        } else if (output.baseMetricScore >= 4.0){
            document.getElementById('id_severity').value = 3;
        } else if (output.baseMetricScore >= 0.1){
            document.getElementById('id_severity').value = 2;
        } else {
            document.getElementById('id_severity').value = 1;
        }
        
        const scoreRatings = document.querySelectorAll('.scoreRating');
        scoreRatings[0].className = "scoreRating " + output.baseSeverity.toLowerCase();
        document.getElementById("baseMetricScore").textContent = output.baseMetricScore;
        document.getElementById("baseSeverity").textContent = "(" + output.baseSeverity + ")";
        scoreRatings[1].className = "scoreRating " + output.temporalSeverity.toLowerCase();
        document.getElementById("temporalMetricScore").textContent = output.temporalMetricScore;
        document.getElementById("temporalSeverity").textContent = "(" + output.temporalSeverity + ")";
        scoreRatings[2].className = "scoreRating " + output.environmentalSeverity.toLowerCase();
        document.getElementById("environmentalMetricScore").textContent = output.environmentalMetricScore;
        document.getElementById("environmentalSeverity").textContent = "(" + output.environmentalSeverity + ")";

    } else {
        var result = "An error occurred. The error type is '" + output.errorType + 
                     "' and the metrics with errors are " + output.errorMetrics + ".";
        console.error(result);
    }
}